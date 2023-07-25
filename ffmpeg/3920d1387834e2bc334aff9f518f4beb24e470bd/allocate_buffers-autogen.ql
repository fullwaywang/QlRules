/**
 * @name ffmpeg-3920d1387834e2bc334aff9f518f4beb24e470bd-allocate_buffers
 * @id cpp/ffmpeg/3920d1387834e2bc334aff9f518f4beb24e470bd/allocate-buffers
 * @description ffmpeg-3920d1387834e2bc334aff9f518f4beb24e470bd-libavcodec/alac.c-allocate_buffers CVE-2013-0855
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter valac_542, MulExpr target_2, RelationalOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="max_samples_per_frame"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_542
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="536870911"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_size_545, ExprStmt target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_size_545
		and target_1.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter valac_542, MulExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="max_samples_per_frame"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_542
		and target_2.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_3(Function func, Initializer target_3) {
		target_3.getExpr() instanceof MulExpr
		and target_3.getExpr().getEnclosingFunction() = func
}

predicate func_4(Parameter valac_542, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_4.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_542
		and target_4.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_4.getGreaterOperand().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_4.getGreaterOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="channels"
		and target_4.getGreaterOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_542
}

predicate func_5(Variable vbuf_size_545, Parameter valac_542, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="predict_error_buffer"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_542
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_size_545
}

from Function func, Variable vbuf_size_545, Parameter valac_542, MulExpr target_2, Initializer target_3, RelationalOperation target_4, ExprStmt target_5
where
not func_0(valac_542, target_2, target_4, func)
and not func_1(vbuf_size_545, target_5, func)
and func_2(valac_542, target_2)
and func_3(func, target_3)
and func_4(valac_542, target_4)
and func_5(vbuf_size_545, valac_542, target_5)
and vbuf_size_545.getType().hasName("int")
and valac_542.getType().hasName("ALACContext *")
and vbuf_size_545.(LocalVariable).getFunction() = func
and valac_542.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
