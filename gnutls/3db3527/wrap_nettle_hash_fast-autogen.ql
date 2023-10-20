/**
 * @name gnutls-3db352734472d851318944db13be73da61300568-wrap_nettle_hash_fast
 * @id cpp/gnutls/3db352734472d851318944db13be73da61300568/wrap-nettle-hash-fast
 * @description gnutls-3db352734472d851318944db13be73da61300568-wrap_nettle_hash_fast CVE-2021-4209
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtext_size_781, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtext_size_781
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vtext_size_781, Variable vctx_784, Parameter vtext_781, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="update"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_784
		and target_1.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vctx_784
		and target_1.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vtext_size_781
		and target_1.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vtext_781
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vtext_size_781, Variable vctx_784, Parameter vtext_781
where
not func_0(vtext_size_781, func)
and func_1(vtext_size_781, vctx_784, vtext_781, func)
and vtext_size_781.getType().hasName("size_t")
and vctx_784.getType().hasName("nettle_hash_ctx")
and vtext_781.getType().hasName("const void *")
and vtext_size_781.getParentScope+() = func
and vctx_784.getParentScope+() = func
and vtext_781.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
