/**
 * @name ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-z2grestoreall
 * @id cpp/ghostscript/3e5d316b72e3965b7968bb1d96baa137cd063ac6/z2grestoreall
 * @description ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-psi/zdevice2.c-z2grestoreall CVE-2018-16802
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_7, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(NotExpr target_6, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getType().hasName("int")
		and target_1.getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vdone_301, Parameter vi_ctx_p_297, FunctionCall target_8, FunctionCall target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_grestore")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vdone_301
		and target_2.getElse() instanceof ReturnStmt
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vi_ctx_p_297, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="pgs"
		and target_3.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_4(Parameter vi_ctx_p_297, FunctionCall target_4) {
		target_4.getTarget().hasName("gs_gstate_saved")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
		and target_4.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_5(Parameter vi_ctx_p_297, NotExpr target_6, ReturnStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("push_callout")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_297
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%grestoreallpagedevice"
		and target_5.getParent().(IfStmt).getCondition()=target_6
}

predicate func_6(Parameter vi_ctx_p_297, BlockStmt target_7, NotExpr target_6) {
		target_6.getOperand().(FunctionCall).getTarget().hasName("restore_page_device")
		and target_6.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_6.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
		and target_6.getOperand().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(Variable vdone_301, Parameter vi_ctx_p_297, BlockStmt target_7) {
		target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_grestore")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
		and target_7.getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vdone_301
}

predicate func_8(Parameter vi_ctx_p_297, FunctionCall target_8) {
		target_8.getTarget().hasName("gs_gstate_saved")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="pgs"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_297
}

predicate func_9(Parameter vi_ctx_p_297, FunctionCall target_9) {
		target_9.getTarget().hasName("push_callout")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_297
		and target_9.getArgument(1).(StringLiteral).getValue()="%grestoreallpagedevice"
}

from Function func, Variable vdone_301, Parameter vi_ctx_p_297, PointerFieldAccess target_3, FunctionCall target_4, ReturnStmt target_5, NotExpr target_6, BlockStmt target_7, FunctionCall target_8, FunctionCall target_9
where
not func_0(target_7, func)
and not func_1(target_6, func)
and not func_2(vdone_301, vi_ctx_p_297, target_8, target_9)
and func_3(vi_ctx_p_297, target_3)
and func_4(vi_ctx_p_297, target_4)
and func_5(vi_ctx_p_297, target_6, target_5)
and func_6(vi_ctx_p_297, target_7, target_6)
and func_7(vdone_301, vi_ctx_p_297, target_7)
and func_8(vi_ctx_p_297, target_8)
and func_9(vi_ctx_p_297, target_9)
and vdone_301.getType().hasName("bool")
and vi_ctx_p_297.getType().hasName("i_ctx_t *")
and vdone_301.(LocalVariable).getFunction() = func
and vi_ctx_p_297.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
