//! Macros for defining model states and models that progress through those states.
//!
//! This module provides procedural macros for defining compile-time safe models
mod dsl;

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, parse_quote, Data, DataEnum, DeriveInput, Fields, Type, Variant};

/// Stores information about a state in the model.
struct StateInfo {
    /// The name of the state (e.g., "InitialState").
    state_name: String,
    /// The data type associated with the state (e.g., "()", "FirstPassResult").
    state_data_type: String,
    /// The name of the getter method for accessing the state's data (e.g., "first_pass_result").
    getter_name: String,
    /// The name of the `Has*` trait associated with the state's data (e.g., "HasFirstPassResult").
    has_trait_name: String,
    /// Indicates whether the state has a unit type (`()`) as its data.
    is_unit: bool,
}

/// A static, thread-safe map to store state information for different models.
static STATE_INFOS: OnceLock<Mutex<HashMap<String, Vec<StateInfo>>>> = OnceLock::new();

/// Retrieves the global state information map.
fn get_state_infos() -> &'static Mutex<HashMap<String, Vec<StateInfo>>> {
    STATE_INFOS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Builds a vector of `StateInfo` structs from the variants of a data enum.
fn build_state_info(data_enum: &DataEnum) -> syn::Result<Vec<StateInfo>> {
    let mut state_infos = Vec::new();

    for variant in &data_enum.variants {
        let state_info = state_info(variant)?;
        state_infos.push(state_info);
    }
    Ok(state_infos)
}

/// Extracts `StateInfo` from a given enum variant.
fn state_info(variant: &Variant) -> syn::Result<StateInfo> {
    let Fields::Unnamed(fields) = &variant.fields else {
        return Err(syn::Error::new_spanned(
            &variant.fields,
            "Each state variant must have exactly one unnamed field",
        ));
    };
    if fields.unnamed.len() != 1 {
        return Err(syn::Error::new_spanned(
            &variant.fields,
            "Each state variant must have exactly one unnamed field",
        ));
    }
    let field = fields.unnamed.first().unwrap();
    let state_type = &field.ty;

    let type_name = extract_type_name(state_type)?;

    let has_trait_name = format_ident!("Has{}", type_name);
    let getter_name = format_ident!("{}", to_snake_case(&type_name.to_string()));
    let is_unit = if let Type::Tuple(tuple) = state_type {
        tuple.elems.is_empty()
    } else {
        false
    };
    Ok(StateInfo {
        state_name: variant.ident.to_string(),
        state_data_type: quote!(#state_type).to_string(),
        getter_name: getter_name.to_string(),
        has_trait_name: has_trait_name.to_string(),
        is_unit,
    })
}

/// Converts a CamelCase string to snake_case.
fn to_snake_case(s: &str) -> String {
    heck::AsSnakeCase(s).to_string()
}

/// Macro for defining states for a model.
///
/// This macro takes an enum definition that specifies the possible states of a model
/// and their associated data types, and generates:
/// 1. A marker trait with the same name as the enum.
/// 2. Marker structs for each enum variant.
/// 3. `Has*` traits for each data type associated with a state.
/// 4. Implementations of the marker trait and `Has*` traits for each state.
///
/// # Example
///
/// ```rust
/// #[states]
/// enum ModelState {
///     InitialState(()),
///     FirstPassComplete(FirstPassResult),
///     SecondPassComplete(SecondPassResult),
///     AggregationComplete(AggregationResult),
///     Done(FinalSummary),
/// }
/// ```
#[proc_macro_attribute]
pub fn states(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let output = handle_states(parse_macro_input!(item as DeriveInput));
    match output {
        Ok(output) => output.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Handles the `states` macro logic.
fn handle_states(input: DeriveInput) -> syn::Result<TokenStream> {
    let trait_name = &input.ident;
    let enum_data = match &input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "states attribute can only be applied to enums",
            ))
        }
    };

    let states = build_state_info(enum_data)?;

    let mut state_marker_structs = Vec::new();
    let mut has_trait_defs = Vec::new();
    let mut has_trait_impls = Vec::new();

    let mut last_non_unit_has_trait: Option<proc_macro2::Ident> = None;

    for (idx, state) in states.iter().enumerate() {
        let state_name = format_ident!("{}", &state.state_name);

        let state_struct = quote! {
            pub struct #state_name {}

            impl #trait_name for #state_name {}
        };
        state_marker_structs.push(state_struct);

        if !state.is_unit {
            let has_trait_name = format_ident!("{}", &state.has_trait_name);

            let supertrait_bound = last_non_unit_has_trait
                .as_ref()
                .map(|prev_trait| quote! { : #prev_trait });

            let has_trait_def = quote! {
                pub trait #has_trait_name #supertrait_bound {}
            };
            has_trait_defs.push(has_trait_def);

            for later_state_idx in idx..states.len() {
                let later_state = &states[later_state_idx];
                let later_state_name = format_ident!("{}", &later_state.state_name);

                let has_impl = quote! {
                    impl #has_trait_name for #later_state_name {}
                };
                has_trait_impls.push(has_impl);
            }

            last_non_unit_has_trait = Some(has_trait_name.clone());
        }
    }
    get_state_infos()
        .lock()
        .unwrap()
        .insert(trait_name.to_string(), states);

    let output = quote! {
        pub trait #trait_name {}

        #(#state_marker_structs)*

        #(#has_trait_defs)*

        #(#has_trait_impls)*
    };

    Ok(output.into())
}

/// Extracts the type name from a `Type::Path`.
fn extract_type_name(ty: &Type) -> syn::Result<proc_macro2::Ident> {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .ok_or_else(|| {
                syn::Error::new_spanned(type_path, "Type path should have at least one segment")
            })
            .map(|segment| segment.ident.clone()),
        _ => Err(syn::Error::new_spanned(
            ty,
            "Unsupported field type: only simple type paths are supported",
        )),
    }
}

/// Macro for defining a model that transitions through states.
///
/// This macro takes a struct definition with a type parameter bounded by a ModelState trait
/// and generates methods for transitioning the model through its states. It also automatically
/// adds a `_state: PhantomData<S>` field to the struct.
///
/// # Example
///
/// ```rust
/// #[model]
/// pub struct Model<S: ModelState> {
///     // User-defined fields go here
///     data: HashMap<String, String>,
///     state_data: Option<Box<dyn Any>>,
///     // The macro adds _state: PhantomData<S> automatically
/// }
/// ```
#[proc_macro_attribute]
pub fn model(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as DeriveInput);
    match handle_model(&mut input) {
        Ok(output) => output.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Handles the `model` macro logic.
fn handle_model(input: &mut DeriveInput) -> Result<TokenStream, syn::Error> {
    let model_name = &input.ident;
    let generics = &input.generics;

    if generics.params.len() != 1 {
        panic!("model attribute can only be applied to structs with exactly one type parameter");
    }

    let type_param = generics.params.first().unwrap();
    let state_type_param = match type_param {
        syn::GenericParam::Type(param) => param,
        _ => panic!("model attribute requires a type parameter"),
    };

    let state_param_name = &state_type_param.ident;

    let state_trait_name = state_type_param
        .bounds
        .iter()
        .find_map(|b| {
            if let syn::TypeParamBound::Trait(t) = b {
                Some(t.path.segments.last().unwrap().ident.to_string())
            } else {
                None
            }
        })
        .unwrap();
    let state_infos = get_state_infos().lock().unwrap();
    let Some(state_info) = state_infos.get(&state_trait_name) else {
        panic!("The trait bound is not a valid state trait");
    };

    let original_fields = match &input.data {
        syn::Data::Struct(ref struct_data) => match &struct_data.fields {
            syn::Fields::Named(fields) => fields.named.clone(),
            _ => panic!("model macro currently only supports structs with named fields"),
        },
        _ => panic!("model macro can only be applied to structs"),
    };

    match &mut input.data {
        syn::Data::Struct(ref mut struct_data) => match &mut struct_data.fields {
            syn::Fields::Named(fields) => {
                fields.named.push(parse_quote! {
                    _state: PhantomData<#state_param_name>
                });

                for info in state_info {
                    if !info.is_unit {
                        let field_name = format_ident!("{}", &info.getter_name);
                        let field_type: Type = syn::parse_str(&info.state_data_type)?;
                        fields.named.push(parse_quote! {
                            #field_name: Option<#field_type>
                        });
                    }
                }
            }
            syn::Fields::Unnamed(_) => {
                panic!("model macro currently only supports structs with named fields");
            }
            syn::Fields::Unit => {
                panic!("model macro cannot add fields to unit structs");
            }
        },
        _ => panic!("model macro can only be applied to structs"),
    };

    let initial_state = format_ident!("{}", &state_info[0].state_name);
    let initial_state_info = &state_info[0];

    // --- Generate Constructor ---
    let mut initializers = vec![];
    initializers.push(quote! { _state: ::std::marker::PhantomData });

    let mut constructor_params = vec![];
    for field in original_fields.iter() {
        let field_name = &field.ident;
        let field_ty = &field.ty;
        initializers.push(quote! { #field_name: #field_name });
        constructor_params.push(quote! { #field_name: #field_ty });
    }

    if !initial_state_info.is_unit {
        let initial_data_type: Type = syn::parse_str(&initial_state_info.state_data_type)?;
        let _initial_data_type = initial_data_type; // Suppress unused warning
        let initial_field_name = format_ident!("{}", &initial_state_info.getter_name);
        let param_name = format_ident!("{}", to_snake_case(&initial_state_info.state_data_type));

        constructor_params.push(quote! { #param_name: #_initial_data_type });
        initializers.push(quote! { #initial_field_name: Some(#param_name) });
    } else {
        let initial_field_name = format_ident!("{}", &initial_state_info.getter_name);
        if state_info
            .iter()
            .any(|si| si.getter_name == initial_state_info.getter_name && !si.is_unit)
        {
            initializers.push(quote! { #initial_field_name: Some(()) });
        }
    }

    for info in state_info.iter().skip(1) {
        if !info.is_unit {
            let field_name = format_ident!("{}", &info.getter_name);
            initializers.push(quote! { #field_name: None });
        }
    }

    let constructor = quote! {
        impl #model_name<#initial_state> {
            pub fn new(#(#constructor_params),*) -> Self {
                Self {
                    #(#initializers),*
                }
            }
        }
    };

    // --- Generate Transitions ---
    let mut transition_blocks = vec![];

    for (i, current_info) in state_info.iter().enumerate().take(state_info.len() - 1) {
        let current_state = format_ident!("{}", &current_info.state_name);
        let next_info = &state_info[i + 1];
        let next_state = format_ident!("{}", &next_info.state_name);
        let transition_method = format_ident!("with_{}", to_snake_case(&next_info.state_data_type));

        let transition_impl = if next_info.is_unit {
            quote! {
               impl #model_name<#current_state> {
                   pub fn #transition_method(self) -> #model_name<#next_state> {
                       unsafe {
                           std::mem::transmute(self)
                       }
                   }
               }
            }
        } else {
            let next_data_type: Type = syn::parse_str(&next_info.state_data_type)?;
            let param_name = format_ident!("{}", to_snake_case(&next_info.state_data_type));
            let field_to_set = format_ident!("{}", &next_info.getter_name);

            quote! {
                impl #model_name<#current_state> {
                    pub fn #transition_method(mut self, #param_name: #next_data_type) -> #model_name<#next_state> {
                       self.#field_to_set = Some(#param_name);
                       unsafe {
                        std::mem::transmute(self)
                       }
                    }
                }
            }
        };
        transition_blocks.push(transition_impl);
    }

    // --- Generate Getters ---
    let mut getters_blocks = vec![];
    let state_trait_name = format_ident!("{}", state_trait_name);
    for info in state_info {
        if info.is_unit {
            continue;
        }

        let has_trait_name = format_ident!("{}", &info.has_trait_name);
        let data_type: Type = syn::parse_str(&info.state_data_type)?;
        let getter_method = format_ident!("{}", &info.getter_name);
        let field_name = format_ident!("{}", &info.getter_name);

        let getter_impl = quote! {
            impl<#state_param_name: #state_trait_name> #model_name<#state_param_name> where #state_param_name: #has_trait_name {
                pub fn #getter_method(&self) -> &#data_type {
                    self.#field_name.as_ref().unwrap()
                }
            }
        };
        getters_blocks.push(getter_impl);
    }

    let combined = quote! {
        #input
        #constructor
        #(#transition_blocks)*
        #(#getters_blocks)*
    };

    Ok(combined.into())
}

/*
#[proc_macro]
pub fn build_expr(input: TokenStream) -> TokenStream {
    parse_macro_input!(input as dsl::FullExpressionParser).into()
}
*/

#[proc_macro]
pub fn build_expr(input: TokenStream) -> TokenStream {
    parse_macro_input!(input as dsl::VersionedRelativeMemory)
        .to_expr_tokens()
        .into()
}
