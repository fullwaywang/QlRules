/**
 * @name ffmpeg-204cb29b3c84a74cbcd059d353c70c8bdc567d98-shorten_decode_close
 * @id cpp/ffmpeg/204cb29b3c84a74cbcd059d353c70c8bdc567d98/shorten-decode-close
 * @description ffmpeg-204cb29b3c84a74cbcd059d353c70c8bdc567d98-libavcodec/shorten.c-shorten_decode_close CVE-2012-0858
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_614, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="decoded"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_614
}

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue() instanceof ArrayExpr
		and target_1.getRValue().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vs_614, Variable vi_615, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="decoded"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vi_615
}

predicate func_3(Variable vs_614, AssignPointerSubExpr target_3) {
		target_3.getLValue() instanceof ArrayExpr
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="nwrap"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
}

from Function func, Variable vs_614, Variable vi_615, PointerFieldAccess target_0, ArrayExpr target_2, AssignPointerSubExpr target_3
where
func_0(vs_614, target_0)
and not func_1(func)
and func_2(vs_614, vi_615, target_2)
and func_3(vs_614, target_3)
and vs_614.getType().hasName("ShortenContext *")
and vi_615.getType().hasName("int")
and vs_614.(LocalVariable).getFunction() = func
and vi_615.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
