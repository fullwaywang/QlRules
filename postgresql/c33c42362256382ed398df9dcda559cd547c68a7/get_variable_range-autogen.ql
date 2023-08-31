/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-get_variable_range
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/get-variable-range
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/selfuncs.c-get_variable_range CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvardata_4860, NotExpr target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_4860
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AssignExpr).getLValue().(VariableAccess).getType().hasName("Oid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_3.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsortop_4860, FunctionCall target_2) {
		target_2.getTarget().hasName("get_opcode")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vsortop_4860
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fmgr_info")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("FmgrInfo")
}

predicate func_3(Parameter vvardata_4860, NotExpr target_3) {
		target_3.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_3.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_4860
		and target_3.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vvardata_4860, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("get_typlenbyval")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_4860
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int16")
		and target_4.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

from Function func, Parameter vvardata_4860, Parameter vsortop_4860, FunctionCall target_2, NotExpr target_3, ExprStmt target_4
where
not func_0(vvardata_4860, target_3, target_4, func)
and func_2(vsortop_4860, target_2)
and func_3(vvardata_4860, target_3)
and func_4(vvardata_4860, target_4)
and vvardata_4860.getType().hasName("VariableStatData *")
and vsortop_4860.getType().hasName("Oid")
and vvardata_4860.getFunction() = func
and vsortop_4860.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
