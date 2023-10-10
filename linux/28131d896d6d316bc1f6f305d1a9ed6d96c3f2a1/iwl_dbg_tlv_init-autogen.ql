/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbg_tlv_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dbg-tlv-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbg_tlv_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_455) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="1296"
		and target_0.getExprOperand().(ValueFieldAccess).getTarget().getName()="time_point"
		and target_0.getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dbg"
		and target_0.getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_455)
}

predicate func_1(Parameter vtrans_455) {
	exists(SizeofExprOperator target_1 |
		target_1.getValue()="48"
		and target_1.getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="time_point"
		and target_1.getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dbg"
		and target_1.getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_455
		and target_1.getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_2(Variable vtp_463) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("INIT_LIST_HEAD")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="config_list"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtp_463)
}

predicate func_3(Variable vtp_463) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="active_trig_list"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtp_463)
}

from Function func, Variable vtp_463, Parameter vtrans_455
where
func_0(vtrans_455)
and func_1(vtrans_455)
and not func_2(vtp_463)
and vtp_463.getType().hasName("iwl_dbg_tlv_time_point_data *")
and func_3(vtp_463)
and vtrans_455.getType().hasName("iwl_trans *")
and vtp_463.getParentScope+() = func
and vtrans_455.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
