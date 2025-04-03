use super::model::{BlockId, FunctionId, ProgramModel};

use super::dispatching::event_types_enum;

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
}
