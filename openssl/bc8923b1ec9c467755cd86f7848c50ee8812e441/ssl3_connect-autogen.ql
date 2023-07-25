/**
 * @name openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_connect
 * @id cpp/openssl/bc8923b1ec9c467755cd86f7848c50ee8812e441/ssl3-connect
 * @description openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_connect CVE-2014-0224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_186) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_186
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_186)
}

predicate func_1(Parameter vs_186) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="init_num"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_186
		and target_1.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vs_186
where
not func_0(vs_186)
and vs_186.getType().hasName("SSL *")
and func_1(vs_186)
and vs_186.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
