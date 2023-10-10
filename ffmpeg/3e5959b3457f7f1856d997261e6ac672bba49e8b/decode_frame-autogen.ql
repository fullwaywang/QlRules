/**
 * @name ffmpeg-3e5959b3457f7f1856d997261e6ac672bba49e8b-decode_frame
 * @id cpp/ffmpeg/3e5959b3457f7f1856d997261e6ac672bba49e8b/decode-frame
 * @description ffmpeg-3e5959b3457f7f1856d997261e6ac672bba49e8b-libavcodec/exr.c-decode_frame CVE-2020-35965
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1691, BlockStmt target_2, RelationalOperation target_3) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ymin"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_0.getThen().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_0.getElse().(PointerFieldAccess).getTarget().getName()="ymin"
		and target_0.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ymin"
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_2
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1691, BlockStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="ymin"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_1691
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
}

predicate func_3(Variable vs_1691, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ymin"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1691
}

from Function func, Variable vs_1691, PointerFieldAccess target_1, BlockStmt target_2, RelationalOperation target_3
where
not func_0(vs_1691, target_2, target_3)
and func_1(vs_1691, target_2, target_1)
and func_2(target_2)
and func_3(vs_1691, target_3)
and vs_1691.getType().hasName("EXRContext *")
and vs_1691.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
