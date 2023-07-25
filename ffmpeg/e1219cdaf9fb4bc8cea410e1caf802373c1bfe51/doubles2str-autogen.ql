/**
 * @name ffmpeg-e1219cdaf9fb4bc8cea410e1caf802373c1bfe51-doubles2str
 * @id cpp/ffmpeg/e1219cdaf9fb4bc8cea410e1caf802373c1bfe51/doubles2str
 * @description ffmpeg-e1219cdaf9fb4bc8cea410e1caf802373c1bfe51-libavcodec/tiff.c-doubles2str CVE-2013-0874
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vcount_217, Variable vcomponent_len_221, MulExpr target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_217
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getValue()="2147483646"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vcomponent_len_221
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(AddExpr target_2 |
		target_2.getAnOperand() instanceof MulExpr
		and target_2.getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vcount_217, Variable vcomponent_len_221, MulExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vcomponent_len_221
		and target_3.getRightOperand().(VariableAccess).getTarget()=vcount_217
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_4(Variable vcomponent_len_221, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcomponent_len_221
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="15"
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
}

from Function func, Parameter vcount_217, Variable vcomponent_len_221, MulExpr target_3, ExprStmt target_4
where
not func_1(vcount_217, vcomponent_len_221, target_3, target_4, func)
and not func_2(func)
and func_3(vcount_217, vcomponent_len_221, target_3)
and func_4(vcomponent_len_221, target_4)
and vcount_217.getType().hasName("int")
and vcomponent_len_221.getType().hasName("int")
and vcount_217.getFunction() = func
and vcomponent_len_221.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
