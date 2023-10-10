/**
 * @name linux-ad5d07f4a9cd671233ae20983848874731102c08-cipso_v4_doi_putdef
 * @id cpp/linux/ad5d07f4a9cd671233ae20983848874731102c08/cipso_v4_doi_putdef
 * @description linux-ad5d07f4a9cd671233ae20983848874731102c08-cipso_v4_doi_putdef 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vcipso_v4_doi_list_lock, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcipso_v4_doi_list_lock
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vdoi_def_581, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("list_del_rcu")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoi_def_581
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vcipso_v4_doi_list_lock, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcipso_v4_doi_list_lock
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vdoi_def_581, Variable vcipso_v4_doi_list_lock
where
func_0(vcipso_v4_doi_list_lock, func)
and func_1(vdoi_def_581, func)
and func_2(vcipso_v4_doi_list_lock, func)
and vdoi_def_581.getType().hasName("cipso_v4_doi *")
and vcipso_v4_doi_list_lock.getType().hasName("spinlock_t")
and vdoi_def_581.getParentScope+() = func
and not vcipso_v4_doi_list_lock.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
