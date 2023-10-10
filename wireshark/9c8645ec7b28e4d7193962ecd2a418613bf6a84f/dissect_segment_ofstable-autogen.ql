/**
 * @name wireshark-9c8645ec7b28e4d7193962ecd2a418613bf6a84f-dissect_segment_ofstable
 * @id cpp/wireshark/9c8645ec7b28e4d7193962ecd2a418613bf6a84f/dissect-segment-ofstable
 * @description wireshark-9c8645ec7b28e4d7193962ecd2a418613bf6a84f-epan/dissectors/packet-lbmpdm.c-dissect_segment_ofstable CVE-2018-19623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdatalen_850, Variable vdatalen_remaining_852, ExprStmt target_9, LogicalAndExpr target_8, VariableAccess target_0) {
		target_0.getTarget()=vdatalen_850
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdatalen_remaining_852
		and target_9.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vdatalen_remaining_852, VariableAccess target_1) {
		target_1.getTarget()=vdatalen_remaining_852
}

predicate func_2(Variable vid_list_856, Variable vofs_list_857, ExprStmt target_11, RelationalOperation target_12, ExprStmt target_13, RelationalOperation target_14) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vid_list_856
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vofs_list_857
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("except_throw")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_12.getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_14.getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

/*predicate func_3(Function func) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("except_throw")
		and target_3.getArgument(0).(Literal).getValue()="1"
		and target_3.getArgument(1).(Literal).getValue()="2"
		and target_3.getArgument(2).(Literal).getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

*/
predicate func_4(Variable vfield_count_854, Variable vidx_855, BlockStmt target_15, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vidx_855
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vfield_count_854
		and target_4.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_4.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_15
}

predicate func_6(Function func, DeclStmt target_6) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vdatalen_850, Variable vdatalen_remaining_852, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vdatalen_remaining_852
		and target_7.getRValue().(VariableAccess).getTarget()=vdatalen_850
}

predicate func_8(Variable vdatalen_remaining_852, BlockStmt target_15, LogicalAndExpr target_8) {
		target_8.getAnOperand() instanceof RelationalOperation
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_remaining_852
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(SizeofTypeOperator).getValue()="8"
		and target_8.getParent().(ForStmt).getStmt()=target_15
}

predicate func_9(Variable vdatalen_850, Variable vfield_count_854, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_count_854
		and target_9.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vdatalen_850
		and target_9.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
}

predicate func_11(Variable vidx_855, Variable vid_list_856, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vid_list_856
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_855
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lbmpdm_fetch_uint32_encoded")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
}

predicate func_12(Variable vidx_855, Variable vid_list_856, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vid_list_856
		and target_12.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_855
}

predicate func_13(Variable vidx_855, Variable vofs_list_857, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vofs_list_857
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_855
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lbmpdm_fetch_uint32_encoded")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
}

predicate func_14(Variable vidx_855, Variable vofs_list_857, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vofs_list_857
		and target_14.getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_855
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_15.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(SizeofTypeOperator).getType() instanceof LongType
		and target_15.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(SizeofTypeOperator).getValue()="8"
		and target_15.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_15.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_item_add_subtree")
}

from Function func, Variable vdatalen_850, Variable vdatalen_remaining_852, Variable vfield_count_854, Variable vidx_855, Variable vid_list_856, Variable vofs_list_857, VariableAccess target_0, VariableAccess target_1, RelationalOperation target_4, DeclStmt target_6, AssignExpr target_7, LogicalAndExpr target_8, ExprStmt target_9, ExprStmt target_11, RelationalOperation target_12, ExprStmt target_13, RelationalOperation target_14, BlockStmt target_15
where
func_0(vdatalen_850, vdatalen_remaining_852, target_9, target_8, target_0)
and func_1(vdatalen_remaining_852, target_1)
and not func_2(vid_list_856, vofs_list_857, target_11, target_12, target_13, target_14)
and func_4(vfield_count_854, vidx_855, target_15, target_4)
and func_6(func, target_6)
and func_7(vdatalen_850, vdatalen_remaining_852, target_7)
and func_8(vdatalen_remaining_852, target_15, target_8)
and func_9(vdatalen_850, vfield_count_854, target_9)
and func_11(vidx_855, vid_list_856, target_11)
and func_12(vidx_855, vid_list_856, target_12)
and func_13(vidx_855, vofs_list_857, target_13)
and func_14(vidx_855, vofs_list_857, target_14)
and func_15(target_15)
and vdatalen_850.getType().hasName("int")
and vdatalen_remaining_852.getType().hasName("int")
and vfield_count_854.getType().hasName("int")
and vidx_855.getType().hasName("int")
and vid_list_856.getType().hasName("gint32 *")
and vofs_list_857.getType().hasName("gint32 *")
and vdatalen_850.getParentScope+() = func
and vdatalen_remaining_852.getParentScope+() = func
and vfield_count_854.getParentScope+() = func
and vidx_855.getParentScope+() = func
and vid_list_856.getParentScope+() = func
and vofs_list_857.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
