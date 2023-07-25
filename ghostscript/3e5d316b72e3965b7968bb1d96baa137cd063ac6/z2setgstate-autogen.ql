/**
 * @name ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-z2setgstate
 * @id cpp/ghostscript/3e5d316b72e3965b7968bb1d96baa137cd063ac6/z2setgstate
 * @description ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-psi/zdevice2.c-z2setgstate CVE-2018-16802
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vi_ctx_p_355, ValueFieldAccess target_6, FunctionCall target_7, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("restore_page_device")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_355
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_355
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof ValueFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(ReturnStmt target_8, Function func) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vi_ctx_p_355, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="pgs"
		and target_3.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_355
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_4(Variable vop_357, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="pstruct"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gstate"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pstruct"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_357
}

predicate func_5(Parameter vi_ctx_p_355, ReturnStmt target_8, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("restore_page_device")
		and target_5.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_5.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_355
		and target_5.getOperand().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_5.getParent().(IfStmt).getThen()=target_8
}

predicate func_6(Parameter vi_ctx_p_355, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="current"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_355
}

predicate func_7(Parameter vi_ctx_p_355, FunctionCall target_7) {
		target_7.getTarget().hasName("zsetgstate")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_355
}

predicate func_8(Parameter vi_ctx_p_355, ReturnStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("zsetgstate")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_355
}

from Function func, Variable vop_357, Parameter vi_ctx_p_355, PointerFieldAccess target_3, ValueFieldAccess target_4, NotExpr target_5, ValueFieldAccess target_6, FunctionCall target_7, ReturnStmt target_8
where
not func_0(vi_ctx_p_355, target_6, target_7, func)
and not func_1(func)
and not func_2(target_8, func)
and func_3(vi_ctx_p_355, target_3)
and func_4(vop_357, target_4)
and func_5(vi_ctx_p_355, target_8, target_5)
and func_6(vi_ctx_p_355, target_6)
and func_7(vi_ctx_p_355, target_7)
and func_8(vi_ctx_p_355, target_8)
and vop_357.getType().hasName("os_ptr")
and vi_ctx_p_355.getType().hasName("i_ctx_t *")
and vop_357.(LocalVariable).getFunction() = func
and vi_ctx_p_355.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
