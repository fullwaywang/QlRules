/**
 * @name linux-8c39e2699f8acb2e29782a834e56306da24937fe-chap_gen_challenge
 * @id cpp/linux/8c39e2699f8acb2e29782a834e56306da24937fe/chap_gen_challenge
 * @description linux-8c39e2699f8acb2e29782a834e56306da24937fe-chap_gen_challenge 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vchallenge_asciihex_45) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("bin2hex")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vchallenge_asciihex_45
		and target_0.getArgument(1) instanceof PointerFieldAccess
		and target_0.getArgument(2) instanceof Literal)
}

predicate func_1(Variable vchap_46) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="challenge"
		and target_1.getQualifier().(VariableAccess).getTarget()=vchap_46
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="16"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vchallenge_asciihex_45) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("chap_binaryhex_to_asciihex")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vchallenge_asciihex_45
		and target_4.getArgument(1) instanceof PointerFieldAccess
		and target_4.getArgument(2) instanceof Literal)
}

from Function func, Variable vchallenge_asciihex_45, Variable vchap_46
where
not func_0(vchallenge_asciihex_45)
and func_1(vchap_46)
and func_3(func)
and func_4(vchallenge_asciihex_45)
and vchallenge_asciihex_45.getType().hasName("unsigned char[33]")
and vchap_46.getType().hasName("iscsi_chap *")
and vchallenge_asciihex_45.getParentScope+() = func
and vchap_46.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
