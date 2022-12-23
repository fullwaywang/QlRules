/**
 * @name linux-ad5d07f4a9cd671233ae20983848874731102c08-cipso_v4_doi_remove
 * @id cpp/linux/ad5d07f4a9cd671233ae20983848874731102c08/cipso_v4_doi_remove
 * @description linux-ad5d07f4a9cd671233ae20983848874731102c08-cipso_v4_doi_remove 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vcipso_v4_doi_list_lock) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("spin_unlock")
		and not target_0.getTarget().hasName("cipso_v4_doi_putdef")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcipso_v4_doi_list_lock)
}

predicate func_1(Variable vcipso_v4_doi_list_lock) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcipso_v4_doi_list_lock
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_3(Variable vret_val_511, Variable vdoi_def_512, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("refcount_dec_and_test")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="refcount"
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoi_def_512
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_val_511
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="16"
		and target_3.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_7(Variable vcipso_v4_doi_list_lock) {
	exists(VariableAccess target_7 |
		target_7.getTarget()=vcipso_v4_doi_list_lock)
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("cipso_v4_cache_invalidate")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable vdoi_def_512, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("call_rcu")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rcu"
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoi_def_512
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Variable vret_val_511, Variable vdoi_def_512, Variable vcipso_v4_doi_list_lock
where
func_0(vcipso_v4_doi_list_lock)
and func_1(vcipso_v4_doi_list_lock)
and func_3(vret_val_511, vdoi_def_512, func)
and func_7(vcipso_v4_doi_list_lock)
and func_8(func)
and func_9(vdoi_def_512, func)
and vret_val_511.getType().hasName("int")
and vdoi_def_512.getType().hasName("cipso_v4_doi *")
and vret_val_511.getParentScope+() = func
and vdoi_def_512.getParentScope+() = func
and not vcipso_v4_doi_list_lock.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
