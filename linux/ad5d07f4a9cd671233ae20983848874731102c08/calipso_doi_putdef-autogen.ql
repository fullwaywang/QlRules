/**
 * @name linux-ad5d07f4a9cd671233ae20983848874731102c08-calipso_doi_putdef
 * @id cpp/linux/ad5d07f4a9cd671233ae20983848874731102c08/calipso_doi_putdef
 * @description linux-ad5d07f4a9cd671233ae20983848874731102c08-calipso_doi_putdef 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vcalipso_doi_list_lock) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("spin_lock")
		and not target_0.getTarget().hasName("calipso_cache_invalidate")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcalipso_doi_list_lock)
}

predicate func_1(Variable vcalipso_doi_list_lock) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vcalipso_doi_list_lock)
}

predicate func_2(Parameter vdoi_def_504, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("list_del_rcu")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoi_def_504
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vcalipso_doi_list_lock, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcalipso_doi_list_lock
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Parameter vdoi_def_504, Variable vcalipso_doi_list_lock
where
func_0(vcalipso_doi_list_lock)
and func_1(vcalipso_doi_list_lock)
and func_2(vdoi_def_504, func)
and func_3(vcalipso_doi_list_lock, func)
and vdoi_def_504.getType().hasName("calipso_doi *")
and vdoi_def_504.getParentScope+() = func
and not vcalipso_doi_list_lock.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
