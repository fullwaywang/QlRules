/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-http_read_header
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/http-read-header
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-http_read_header CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_971, RelationalOperation target_3) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_971
		and target_0.getRValue().(Literal).getValue()="18446744073709551615"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_971, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="chunksize"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_971
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue() instanceof UnaryMinusExpr
}

predicate func_2(Variable vs_971, AssignExpr target_2) {
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_971
		and target_2.getRValue().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Variable vs_971, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_get_line")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_971
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="4096"
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vs_971, PointerFieldAccess target_1, AssignExpr target_2, RelationalOperation target_3
where
not func_0(vs_971, target_3)
and func_1(vs_971, target_1)
and func_2(vs_971, target_2)
and func_3(vs_971, target_3)
and vs_971.getType().hasName("HTTPContext *")
and vs_971.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
