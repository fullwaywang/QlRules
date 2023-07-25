/**
 * @name openssl-bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b-dtls1_reassemble_fragment
 * @id cpp/openssl/bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b/dtls1-reassemble-fragment
 * @description openssl-bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b-dtls1_reassemble_fragment CVE-2014-3505
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfrag_599, Variable vitem_600) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_600
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_599)
}

predicate func_1(Variable vfrag_599) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vfrag_599
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_599)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vitem_600, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_600
		and target_4.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem_600
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vfrag_599, Variable vitem_600
where
not func_0(vfrag_599, vitem_600)
and func_1(vfrag_599)
and func_3(func)
and func_4(vitem_600, func)
and vfrag_599.getType().hasName("hm_fragment *")
and vitem_600.getType().hasName("pitem *")
and vfrag_599.getParentScope+() = func
and vitem_600.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
