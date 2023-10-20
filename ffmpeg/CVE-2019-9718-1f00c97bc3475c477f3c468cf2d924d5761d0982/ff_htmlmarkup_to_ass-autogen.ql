/**
 * @name ffmpeg-1f00c97bc3475c477f3c468cf2d924d5761d0982-ff_htmlmarkup_to_ass
 * @id cpp/ffmpeg/1f00c97bc3475c477f3c468cf2d924d5761d0982/ff-htmlmarkup-to-ass
 * @description ffmpeg-1f00c97bc3475c477f3c468cf2d924d5761d0982-libavcodec/htmlsubtitles.c-ff_htmlmarkup_to_ass CVE-2019-9718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vin_82, Variable vbuffer_84, Variable vlen_85, Variable vtag_close_85, FunctionCall target_0) {
		target_0.getTarget().hasName("sscanf")
		and not target_0.getTarget().hasName("scantag")
		and target_0.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vin_82
		and target_0.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtag_close_85
		and target_0.getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getArgument(1).(StringLiteral).getValue()="%127[^<>]>%n"
		and target_0.getArgument(2).(VariableAccess).getTarget()=vbuffer_84
		and target_0.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlen_85
}

predicate func_1(Variable vlen_85, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand() instanceof FunctionCall
		and target_1.getLesserOperand().(Literal).getValue()="1"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_85
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(2).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_2.getStmt(2).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(3).(IfStmt).getCondition().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_2.getStmt(3).(IfStmt).getCondition().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
		and target_2.getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vin_82, Variable vbuffer_84, Variable vlen_85, Variable vtag_close_85, FunctionCall target_0, RelationalOperation target_1, BlockStmt target_2
where
func_0(vin_82, vbuffer_84, vlen_85, vtag_close_85, target_0)
and func_1(vlen_85, target_2, target_1)
and func_2(target_2)
and vin_82.getType().hasName("const char *")
and vbuffer_84.getType().hasName("char[128]")
and vlen_85.getType().hasName("int")
and vtag_close_85.getType().hasName("int")
and vin_82.getParentScope+() = func
and vbuffer_84.getParentScope+() = func
and vlen_85.getParentScope+() = func
and vtag_close_85.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
