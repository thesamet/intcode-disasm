use super::dispatching::event_types_enum;
use super::model::{BlockId, FunctionId, ProgramModel};

event_types_enum! {Event, ProgramModel,
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct ImageAddedEvent { }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct ImageScannerComplete {
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct BlockAddedEvent {
        block_id: BlockId,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct FunctionCfgBuilt {
        pub function_id: FunctionId,
    }

    /// Signals that data flow analysis (reaching definitions, liveness) has completed for a function.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DataFlowAnalysisComplete {
        pub function_id: FunctionId,
    }

    /// Signals that SSA conversion has completed
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SsaConversionComplete {
        pub completed: bool,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct FunctionCallAnalysisComplete {}

    /// Signals that type inference has completed
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TypeInferenceComplete {
        pub completed: bool,
    }
}
