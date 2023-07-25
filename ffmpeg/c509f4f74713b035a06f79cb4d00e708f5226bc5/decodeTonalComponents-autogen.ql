/**
 * @name ffmpeg-c509f4f74713b035a06f79cb4d00e708f5226bc5-decodeTonalComponents
 * @id cpp/ffmpeg/c509f4f74713b035a06f79cb4d00e708f5226bc5/decodeTonalComponents
 * @description ffmpeg-c509f4f74713b035a06f79cb4d00e708f5226bc5-libavcodec/atrac3.c-decodeTonalComponents CVE-2012-0853
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcomponent_count_370, ArrayExpr target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcomponent_count_370
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcomponent_count_370, ArrayExpr target_1) {
		target_1.getArrayBase().(VariableAccess).getTarget().getType().hasName("tonal_component *")
		and target_1.getArrayOffset().(VariableAccess).getTarget()=vcomponent_count_370
}

from Function func, Variable vcomponent_count_370, ArrayExpr target_1
where
not func_0(vcomponent_count_370, target_1)
and func_1(vcomponent_count_370, target_1)
and vcomponent_count_370.getType().hasName("int")
and vcomponent_count_370.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
