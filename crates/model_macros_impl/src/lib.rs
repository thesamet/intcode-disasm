//! Macros for defining model states and models that progress through those states.
use heck::AsSnakeCase;
use proc_macro::TokenStream;
use proc_macro2;
use quote::{format_ident, quote};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};
use syn::{parse_macro_input, parse_quote, Data, DataEnum, DeriveInput, Fields, Type, Variant};

/// Stores information about a state in the model.
#[derive(Clone)] // Added Clone
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
    AsSnakeCase(s).to_string()
}

/// Macro for defining states for a model.
#[proc_macro_attribute]
pub fn states(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    match handle_states(input) {
        Ok(output) => output.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Handles the `states` macro logic.
fn handle_states(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
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

    let states_vec = build_state_info(enum_data)?;

    let mut state_marker_structs = Vec::new();
    let mut has_trait_defs = Vec::new();
    let mut has_trait_impls = Vec::new();

    let mut last_non_unit_has_trait: Option<proc_macro2::Ident> = None;

    for (idx, state) in states_vec.iter().enumerate() {
        let state_name_ident = format_ident!("{}", &state.state_name);

        let state_struct = quote! {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct #state_name_ident {}

            impl #trait_name for #state_name_ident {}
        };
        state_marker_structs.push(state_struct);

        if !state.is_unit {
            let has_trait_name_ident = format_ident!("{}", &state.has_trait_name);

            let supertrait_bound = last_non_unit_has_trait
                .as_ref()
                .map(|prev_trait| quote! { : #prev_trait });

            let has_trait_def = quote! {
                pub trait #has_trait_name_ident #supertrait_bound {}
            };
            has_trait_defs.push(has_trait_def);

            for later_state_idx in idx..states_vec.len() {
                let later_state = &states_vec[later_state_idx];
                let later_state_name_ident = format_ident!("{}", &later_state.state_name);

                let has_impl = quote! {
                    impl #has_trait_name_ident for #later_state_name_ident {}
                };
                has_trait_impls.push(has_impl);
            }

            last_non_unit_has_trait = Some(has_trait_name_ident.clone());
        }
    }
    get_state_infos()
        .lock()
        .unwrap() // Standard to panic on poisoned mutex
        .insert(trait_name.to_string(), states_vec);

    let output = quote! {
        pub trait #trait_name: Sized + Send + Sync + Copy + std::fmt::Debug + PartialEq + Eq + std::hash::Hash {}

        #(#state_marker_structs)*

        #(#has_trait_defs)*

        #(#has_trait_impls)*
    };

    Ok(output)
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
        Type::Tuple(tuple_path) if tuple_path.elems.is_empty() => {
            Ok(format_ident!("Unit")) // Special name for () type
        }
        _ => Err(syn::Error::new_spanned(
            ty,
            "Unsupported field type: only simple type paths or unit type `()` are supported for deriving Has<Trait> names.",
        )),
    }
}

/// Macro for defining a model that transitions through states.
#[proc_macro_attribute]
pub fn model(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as DeriveInput);
    match handle_model(&mut input) {
        Ok(output) => output.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Handles the `model` macro logic.
fn handle_model(input: &mut DeriveInput) -> Result<proc_macro2::TokenStream, syn::Error> {
    let model_name = &input.ident;
    let generics = &input.generics;

    if generics.params.len() != 1 {
        return Err(syn::Error::new_spanned(
            generics,
            "model attribute can only be applied to structs with exactly one type parameter",
        ));
    }

    let type_param = generics.params.first().unwrap();
    let state_type_param = match type_param {
        syn::GenericParam::Type(param) => param,
        _ => {
            return Err(syn::Error::new_spanned(
                type_param,
                "model attribute requires a type parameter",
            ))
        }
    };

    let state_param_name = &state_type_param.ident;

    let state_trait_name_str = state_type_param
        .bounds
        .iter()
        .find_map(|b| {
            if let syn::TypeParamBound::Trait(t) = b {
                t.path.segments.last().map(|seg| seg.ident.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            syn::Error::new_spanned(
                &state_type_param.bounds,
                "Model state parameter must have a trait bound representing the #[states] enum.",
            )
        })?;

    let state_infos_guard = get_state_infos().lock().unwrap(); // Panic on poison
    let state_info_vec_option = state_infos_guard.get(&state_trait_name_str);

    let state_info_vec = match state_info_vec_option {
        Some(siv) => siv.clone(), // Clone to release mutex guard sooner
        None =>  return Err(syn::Error::new_spanned(&state_type_param.bounds, format!("The trait bound '{}' is not a registered state trait. Ensure an `#[states]` enum named '{}' is defined and compiled before this `#[model]` macro.", state_trait_name_str, state_trait_name_str))),
    };
    drop(state_infos_guard);

    if state_info_vec.is_empty() {
        return Err(syn::Error::new_spanned(
            &state_type_param.bounds,
            format!(
                "No states found for '{}'. The #[states] enum must not be empty.",
                state_trait_name_str
            ),
        ));
    }

    let original_fields = match &input.data {
        syn::Data::Struct(ref struct_data) => match &struct_data.fields {
            syn::Fields::Named(fields) => fields.named.clone(),
            _ => {
                return Err(syn::Error::new_spanned(
                    &struct_data.fields,
                    "model macro currently only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "model macro can only be applied to structs",
            ))
        }
    };

    match &mut input.data {
        syn::Data::Struct(ref mut struct_data) => match &mut struct_data.fields {
            syn::Fields::Named(fields) => {
                fields.named.push(parse_quote! {
                    _state: ::std::marker::PhantomData<#state_param_name>
                });

                for info in &state_info_vec {
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
                return Err(syn::Error::new_spanned(
                    &struct_data.fields,
                    "model macro currently only supports structs with named fields",
                ));
            }
            syn::Fields::Unit => {
                return Err(syn::Error::new_spanned(
                    &struct_data.fields,
                    "model macro cannot add fields to unit structs",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "model macro can only be applied to structs",
            ))
        }
    };

    let initial_state_info = &state_info_vec[0];
    let initial_state_ident = format_ident!("{}", &initial_state_info.state_name);

    let mut constructor_params = vec![];
    let mut initializers = vec![quote! { _state: ::std::marker::PhantomData }];

    for field in original_fields.iter() {
        let field_name = &field.ident;
        let field_ty = &field.ty;
        initializers.push(quote! { #field_name: #field_name });
        constructor_params.push(quote! { #field_name: #field_ty });
    }

    if !initial_state_info.is_unit {
        let initial_data_type: Type = syn::parse_str(&initial_state_info.state_data_type)?;
        let initial_field_name = format_ident!("{}", &initial_state_info.getter_name);
        let param_name = format_ident!("{}", to_snake_case(&initial_state_info.state_data_type));

        constructor_params.push(quote! { #param_name: #initial_data_type });
        initializers.push(quote! { #initial_field_name: Some(#param_name) });
    }

    for info in &state_info_vec {
        if !info.is_unit {
            // Add initializer for this field if it's not the initial state's (already handled)
            if !(info.state_name == initial_state_info.state_name && !initial_state_info.is_unit) {
                let field_name = format_ident!("{}", &info.getter_name);
                initializers.push(quote! { #field_name: None });
            }
        }
    }

    let constructor = quote! {
        impl #model_name<#initial_state_ident> {
            pub fn new(#(#constructor_params),*) -> Self {
                Self {
                    #(#initializers),*
                }
            }
        }
    };

    let mut transition_blocks = vec![];
    for (i, current_info) in state_info_vec
        .iter()
        .enumerate()
        .take(state_info_vec.len().saturating_sub(1))
    {
        let current_state_ident = format_ident!("{}", &current_info.state_name);
        let next_info = &state_info_vec[i + 1];
        let next_state_ident = format_ident!("{}", &next_info.state_name);
        let transition_method_name = format_ident!(
            "with_{}",
            to_snake_case(
                &extract_type_name(&syn::parse_str::<Type>(&next_info.state_data_type)?)?
                    .to_string()
            )
        );

        let transition_impl = if next_info.is_unit {
            quote! {
               impl #model_name<#current_state_ident> {
                   pub fn #transition_method_name(self) -> #model_name<#next_state_ident> {
                       unsafe {
                           // This is safe because the layout is the same, only PhantomData changes type.
                           // And PhantomData is a zero-sized type.
                           ::std::mem::transmute(self)
                       }
                   }
               }
            }
        } else {
            let next_data_type: Type = syn::parse_str(&next_info.state_data_type)?;
            let param_name = format_ident!(
                "{}",
                to_snake_case(&extract_type_name(&next_data_type)?.to_string())
            );
            let field_to_set = format_ident!("{}", &next_info.getter_name);

            quote! {
                impl #model_name<#current_state_ident> {
                    pub fn #transition_method_name(mut self, #param_name: #next_data_type) -> #model_name<#next_state_ident> {
                       self.#field_to_set = Some(#param_name);
                       unsafe {
                        // This is safe because the layout is the same, only PhantomData changes type.
                        // And PhantomData is a zero-sized type.
                        ::std::mem::transmute(self)
                       }
                    }
                }
            }
        };
        transition_blocks.push(transition_impl);
    }

    let mut getters_blocks = vec![];
    let state_trait_ident = format_ident!("{}", state_trait_name_str);
    for info in &state_info_vec {
        if info.is_unit {
            continue;
        }

        let has_trait_name_ident = format_ident!("{}", &info.has_trait_name);
        let data_type: Type = syn::parse_str(&info.state_data_type)?;
        let getter_method_ident = format_ident!("{}", &info.getter_name);
        let field_name_ident = format_ident!("{}", &info.getter_name); // This is also the field name

        let getter_impl = quote! {
            impl<#state_param_name: #state_trait_ident> #model_name<#state_param_name> where #state_param_name: #has_trait_name_ident {
                pub fn #getter_method_ident(&self) -> &#data_type {
                    self.#field_name_ident.as_ref().unwrap_or_else(|| {
                        panic!(
                            "Accessed data field '{}' which was None. This indicates either a misuse of the model (not respecting Has{} trait bound) or an internal error in state management.",
                            stringify!(#field_name_ident),
                            stringify!(#has_trait_name_ident)
                        )
                    })
                }
            }
        };
        getters_blocks.push(getter_impl);
    }

    let combined = quote! {
        #input // The original struct definition, now modified with new fields
        #constructor
        #(#transition_blocks)*
        #(#getters_blocks)*
    };

    Ok(combined)
}
