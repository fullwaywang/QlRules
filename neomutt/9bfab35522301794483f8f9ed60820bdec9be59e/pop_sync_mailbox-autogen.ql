/**
 * @name neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop_sync_mailbox
 * @id cpp/neomutt/9bfab35522301794483f8f9ed60820bdec9be59e/pop-sync-mailbox
 * @description neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop.c-pop_sync_mailbox CVE-2018-14362
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_753, Parameter vctx_751, ArrayExpr target_2) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cache_id")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_751
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_753
		and target_2.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_753, Parameter vctx_751, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="data"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_751
		and target_1.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_753
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutt_bcache_del")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bcache"
}

predicate func_2(Variable vi_753, Parameter vctx_751, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_751
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vi_753
}

from Function func, Variable vi_753, Parameter vctx_751, PointerFieldAccess target_1, ArrayExpr target_2
where
not func_0(vi_753, vctx_751, target_2)
and func_1(vi_753, vctx_751, target_1)
and func_2(vi_753, vctx_751, target_2)
and vi_753.getType().hasName("int")
and vctx_751.getType().hasName("Context *")
and vi_753.getParentScope+() = func
and vctx_751.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
