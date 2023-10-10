/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_parse_tlv_firmware
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-parse-tlv-firmware
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_parse_tlv_firmware CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_27(Variable vtlv_len_563, Variable vtlv_type_565, Variable vtlv_data_566, Parameter vdrv_553) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("iwl_drv_set_dump_exclude")
		and target_27.getArgument(0).(VariableAccess).getTarget()=vdrv_553
		and target_27.getArgument(1).(VariableAccess).getTarget()=vtlv_type_565
		and target_27.getArgument(2).(VariableAccess).getTarget()=vtlv_data_566
		and target_27.getArgument(3).(VariableAccess).getTarget()=vtlv_len_563)
}

predicate func_29(Variable vtlv_len_563, Variable vtlv_type_565, Parameter vdrv_553) {
	exists(ExprStmt target_29 |
		target_29.getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_29.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_29.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrv_553
		and target_29.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="TLV %d has invalid size: %u\n"
		and target_29.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtlv_type_565
		and target_29.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtlv_len_563)
}

predicate func_48(Variable vtlv_len_563, Parameter vdrv_553) {
	exists(AssignExpr target_48 |
		target_48.getLValue().(ValueFieldAccess).getTarget().getName()="phy_integration_ver_len"
		and target_48.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fw"
		and target_48.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrv_553
		and target_48.getRValue().(VariableAccess).getTarget()=vtlv_len_563)
}

predicate func_49(Variable vtlv_type_565, Variable v__func__, Parameter vdrv_553) {
	exists(FunctionCall target_49 |
		target_49.getTarget().hasName("__iwl_dbg")
		and target_49.getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_49.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrv_553
		and target_49.getArgument(1).(Literal).getValue()="1"
		and target_49.getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_49.getArgument(4).(StringLiteral).getValue()="unknown TLV: %d\n"
		and target_49.getArgument(5).(VariableAccess).getTarget()=vtlv_type_565)
}

predicate func_50(Variable vtlv_len_563, Variable vtlv_data_566) {
	exists(FunctionCall target_50 |
		target_50.getTarget().hasName("kmemdup")
		and target_50.getArgument(0).(VariableAccess).getTarget()=vtlv_data_566
		and target_50.getArgument(1).(VariableAccess).getTarget()=vtlv_len_563
		and target_50.getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_50.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_50.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3072"
		and target_50.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_50.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_50.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_50.getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

predicate func_51(Parameter vdrv_553) {
	exists(PointerFieldAccess target_51 |
		target_51.getTarget().getName()="dev"
		and target_51.getQualifier().(VariableAccess).getTarget()=vdrv_553)
}

from Function func, Variable vtlv_len_563, Variable vtlv_type_565, Variable vtlv_data_566, Variable v__func__, Parameter vdrv_553
where
not func_27(vtlv_len_563, vtlv_type_565, vtlv_data_566, vdrv_553)
and not func_29(vtlv_len_563, vtlv_type_565, vdrv_553)
and vtlv_len_563.getType().hasName("u32")
and func_48(vtlv_len_563, vdrv_553)
and vtlv_type_565.getType().hasName("iwl_ucode_tlv_type")
and func_49(vtlv_type_565, v__func__, vdrv_553)
and vtlv_data_566.getType().hasName("const u8 *")
and func_50(vtlv_len_563, vtlv_data_566)
and v__func__.getType().hasName("const char[23]")
and vdrv_553.getType().hasName("iwl_drv *")
and func_51(vdrv_553)
and vtlv_len_563.getParentScope+() = func
and vtlv_type_565.getParentScope+() = func
and vtlv_data_566.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vdrv_553.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
