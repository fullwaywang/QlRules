/**
 * @name ffmpeg-8fd8a48263ff1437f9d02d7e78dc63efb9b5ed3a-nsv_parse_NSVf_header
 * @id cpp/ffmpeg/8fd8a48263ff1437f9d02d7e78dc63efb9b5ed3a/nsv-parse-NSVf-header
 * @description ffmpeg-8fd8a48263ff1437f9d02d7e78dc63efb9b5ed3a-libavformat/nsvdec.c-nsv_parse_NSVf_header CVE-2011-3940
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_6, Function func) {
	exists(NotExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("char *")
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(LogicalAndExpr target_5, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnsv_274, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nsvs_file_offset"
		and target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vnsv_274, Variable vtable_entries_used_281, Variable vi_347, RelationalOperation target_7, ExprStmt target_9, ExprStmt target_10, LogicalAndExpr target_5) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof LogicalAndExpr
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_347
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_347
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_347
		and target_3.getThen().(BlockStmt).getStmt(2).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rl32")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vnsv_274, LogicalAndExpr target_5, ExprStmt target_11, ExprStmt target_10) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_5(Variable vpb_275, Variable vtable_entries_280, Variable vtable_entries_used_281, BlockStmt target_6, LogicalAndExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtable_entries_280
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("avio_rl32")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_275
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="843272020"
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(Variable vnsv_274, Variable vtable_entries_used_281, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_7(Variable vtable_entries_used_281, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_7.getLesserOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vnsv_274, Variable vtable_entries_used_281, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsvs_file_offset"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_9(Variable vnsv_274, Variable vpb_275, Variable vi_347, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="nsvs_file_offset"
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_347
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("avio_rl32")
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_275
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

predicate func_10(Variable vnsv_274, Variable vpb_275, Variable vi_347, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_347
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rl32")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_275
}

predicate func_11(Variable vnsv_274, Variable vtable_entries_used_281, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsvs_timestamps"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnsv_274
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtable_entries_used_281
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vnsv_274, Variable vpb_275, Variable vtable_entries_280, Variable vtable_entries_used_281, Variable vi_347, LogicalAndExpr target_5, BlockStmt target_6, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(target_6, func)
and not func_1(target_5, func)
and not func_2(vnsv_274, target_7, target_8, target_9)
and not func_3(vnsv_274, vtable_entries_used_281, vi_347, target_7, target_9, target_10, target_5)
and func_5(vpb_275, vtable_entries_280, vtable_entries_used_281, target_6, target_5)
and func_6(vnsv_274, vtable_entries_used_281, target_6)
and func_7(vtable_entries_used_281, target_7)
and func_8(vnsv_274, vtable_entries_used_281, target_8)
and func_9(vnsv_274, vpb_275, vi_347, target_9)
and func_10(vnsv_274, vpb_275, vi_347, target_10)
and func_11(vnsv_274, vtable_entries_used_281, target_11)
and vnsv_274.getType().hasName("NSVContext *")
and vpb_275.getType().hasName("AVIOContext *")
and vtable_entries_280.getType().hasName("int")
and vtable_entries_used_281.getType().hasName("int")
and vi_347.getType().hasName("int")
and vnsv_274.(LocalVariable).getFunction() = func
and vpb_275.(LocalVariable).getFunction() = func
and vtable_entries_280.(LocalVariable).getFunction() = func
and vtable_entries_used_281.(LocalVariable).getFunction() = func
and vi_347.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
