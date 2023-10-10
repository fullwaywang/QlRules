/**
 * @name ghostscript-d683d1e6450d74619e6277efeebfc222d9a5cb91-zsetmaxlength
 * @id cpp/ghostscript/d683d1e6450d74619e6277efeebfc222d9a5cb91/zsetmaxlength
 * @description ghostscript-d683d1e6450d74619e6277efeebfc222d9a5cb91-psi/zdict.c-zsetmaxlength CVE-2019-3835
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_2, Function func, DoStmt target_0) {
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vi_ctx_p_499, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="in_superexec"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_499
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen() instanceof DoStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vi_ctx_p_499, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="in_superexec"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_499
		and target_2.getAnOperand() instanceof Literal
}

from Function func, Parameter vi_ctx_p_499, DoStmt target_0, IfStmt target_1, EqualityOperation target_2
where
func_0(target_2, func, target_0)
and func_1(vi_ctx_p_499, func, target_1)
and func_2(vi_ctx_p_499, target_2)
and vi_ctx_p_499.getType().hasName("i_ctx_t *")
and vi_ctx_p_499.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
