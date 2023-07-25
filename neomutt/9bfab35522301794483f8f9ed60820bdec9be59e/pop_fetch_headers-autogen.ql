/**
 * @name neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop_fetch_headers
 * @id cpp/neomutt/9bfab35522301794483f8f9ed60820bdec9be59e/pop-fetch-headers
 * @description neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop.c-pop_fetch_headers CVE-2018-14362
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_337, Parameter vctx_290, ArrayExpr target_2, ArrayExpr target_3) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cache_id")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_290
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_337
		and target_2.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_337, Parameter vctx_290, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="data"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_290
		and target_1.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_337
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("mutt_bcache_exists")
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bcache"
}

predicate func_2(Variable vi_337, Parameter vctx_290, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_290
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vi_337
}

predicate func_3(Variable vi_337, Parameter vctx_290, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_290
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_337
}

from Function func, Variable vi_337, Parameter vctx_290, PointerFieldAccess target_1, ArrayExpr target_2, ArrayExpr target_3
where
not func_0(vi_337, vctx_290, target_2, target_3)
and func_1(vi_337, vctx_290, target_1)
and func_2(vi_337, vctx_290, target_2)
and func_3(vi_337, vctx_290, target_3)
and vi_337.getType().hasName("int")
and vctx_290.getType().hasName("Context *")
and vi_337.getParentScope+() = func
and vctx_290.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
