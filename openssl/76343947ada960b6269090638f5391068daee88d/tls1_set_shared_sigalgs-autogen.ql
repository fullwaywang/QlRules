/**
 * @name openssl-76343947ada960b6269090638f5391068daee88d-tls1_set_shared_sigalgs
 * @id cpp/openssl/76343947ada960b6269090638f5391068daee88d/tls1-set-shared-sigalgs
 * @description openssl-76343947ada960b6269090638f5391068daee88d-tls1_set_shared_sigalgs CVE-2015-0291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(ReturnStmt).getParent().(BlockStmt).getStmt(16) instanceof ReturnStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vc_3618) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="shared_sigalgslen"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3618
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3618)
}

predicate func_2(Variable vnmatch_3616, Variable vsalgs_3617) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsalgs_3617
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnmatch_3616)
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getCondition() instanceof NotExpr
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vsalgs_3617, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsalgs_3617
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vpreflen_3615, Variable vallowlen_3615, Variable vnmatch_3616, Variable vsalgs_3617, Variable vpref_3614, Variable vallow_3614, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnmatch_3616
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tls12_do_shared_sigalgs")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsalgs_3617
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpref_3614
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpreflen_3615
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vallow_3614
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vallowlen_3615
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_7(Variable vnmatch_3616) {
	exists(NotExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vnmatch_3616
		and target_7.getParent().(IfStmt).getThen() instanceof ReturnStmt)
}

predicate func_9(Variable vc_3618) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
		and target_9.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3618
		and target_9.getRValue().(Literal).getValue()="0")
}

from Function func, Variable vpreflen_3615, Variable vallowlen_3615, Variable vnmatch_3616, Variable vsalgs_3617, Variable vc_3618, Variable vpref_3614, Variable vallow_3614
where
func_0(func)
and not func_1(vc_3618)
and not func_2(vnmatch_3616, vsalgs_3617)
and func_3(func)
and func_4(vsalgs_3617, func)
and func_5(vpreflen_3615, vallowlen_3615, vnmatch_3616, vsalgs_3617, vpref_3614, vallow_3614, func)
and func_7(vnmatch_3616)
and vpreflen_3615.getType().hasName("size_t")
and vallowlen_3615.getType().hasName("size_t")
and vnmatch_3616.getType().hasName("size_t")
and vsalgs_3617.getType().hasName("TLS_SIGALGS *")
and vc_3618.getType().hasName("CERT *")
and func_9(vc_3618)
and vpref_3614.getType().hasName("const unsigned char *")
and vallow_3614.getType().hasName("const unsigned char *")
and vpreflen_3615.getParentScope+() = func
and vallowlen_3615.getParentScope+() = func
and vnmatch_3616.getParentScope+() = func
and vsalgs_3617.getParentScope+() = func
and vc_3618.getParentScope+() = func
and vpref_3614.getParentScope+() = func
and vallow_3614.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
