/**
 * @name freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-dvcman_receive_channel_data
 * @id cpp/freerdp/baee520e3dd9be6511c45a14c5f5e77784de1471/dvcman-receive-channel-data
 * @description freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-channels/drdynvc/client/drdynvc_main.c-dvcman_receive_channel_data CVE-2018-1000852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchannel_627, Variable vdataSize_628, Parameter vdata_624, FunctionCall target_0) {
		target_0.getTarget().hasName("Stream_Write")
		and not target_0.getTarget().hasName("Stream_Copy")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="dvc_data"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_627
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_624
		and target_0.getArgument(2).(VariableAccess).getTarget()=vdataSize_628
}

predicate func_1(Parameter vdata_624, VariableAccess target_1) {
		target_1.getTarget()=vdata_624
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("Stream_Pointer")
}

from Function func, Variable vchannel_627, Variable vdataSize_628, Parameter vdata_624, FunctionCall target_0, VariableAccess target_1
where
func_0(vchannel_627, vdataSize_628, vdata_624, target_0)
and func_1(vdata_624, target_1)
and vchannel_627.getType().hasName("DVCMAN_CHANNEL *")
and vdataSize_628.getType().hasName("size_t")
and vdata_624.getType().hasName("wStream *")
and vchannel_627.getParentScope+() = func
and vdataSize_628.getParentScope+() = func
and vdata_624.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
