/**
 * @name libwebp-39cb9aad85ca7bb1d193013460db1f8cc6bff109-ReadHuffmanCodes
 * @id cpp/libwebp/39cb9aad85ca7bb1d193013460db1f8cc6bff109/ReadHuffmanCodes
 * @description libwebp-39cb9aad85ca7bb1d193013460db1f8cc6bff109-src/dec/vp8l_dec.c-ReadHuffmanCodes CVE-2020-36332
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="1"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vnum_htree_groups_368, BlockStmt target_83, VariableAccess target_1) {
		target_1.getTarget()=vnum_htree_groups_368
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_83
}

predicate func_2(Variable vnum_htree_groups_368, VariableAccess target_2) {
		target_2.getTarget()=vnum_htree_groups_368
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vnum_htree_groups_368, VariableAccess target_3) {
		target_3.getTarget()=vnum_htree_groups_368
}

predicate func_4(Variable vnum_htree_groups_368, VariableAccess target_4) {
		target_4.getTarget()=vnum_htree_groups_368
}

predicate func_5(Parameter vxsize_358, LogicalOrExpr target_84, VariableAccess target_5) {
		target_5.getTarget()=vxsize_358
		and target_84.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getLocation())
}

predicate func_6(Parameter vysize_358, LogicalOrExpr target_84, VariableAccess target_6) {
		target_6.getTarget()=vysize_358
		and target_84.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getLocation())
}

/*predicate func_7(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, EqualityOperation target_85, ExprStmt target_86, MulExpr target_87, VariableAccess target_7) {
		target_7.getTarget()=vnum_htree_groups_limit_369
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_7.getParent().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_85.getAnOperand().(VariableAccess).getLocation())
		and target_86.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getLocation())
		and target_7.getLocation().isBefore(target_87.getLeftOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_8(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, VariableAccess target_8) {
		target_8.getTarget()=vnum_htree_groups_368
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
}

*/
predicate func_9(Variable vnum_htree_groups_limit_369, ExprStmt target_88, ExprStmt target_89, VariableAccess target_9) {
		target_9.getTarget()=vnum_htree_groups_limit_369
		and target_88.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getLocation())
		and target_9.getLocation().isBefore(target_89.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_10(Variable vnum_htree_groups_limit_369, MulExpr target_87, RelationalOperation target_90, VariableAccess target_10) {
		target_10.getTarget()=vnum_htree_groups_limit_369
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("VP8LHtreeGroupsNew")
		and target_87.getLeftOperand().(VariableAccess).getLocation().isBefore(target_10.getLocation())
		and target_10.getLocation().isBefore(target_90.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_11(Variable vi_360, Variable vnum_htree_groups_limit_369, BlockStmt target_91, ExprStmt target_89, EqualityOperation target_78, VariableAccess target_11) {
		target_11.getTarget()=vnum_htree_groups_limit_369
		and target_11.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_360
		and target_11.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_91
		and target_89.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getLocation())
		and target_11.getLocation().isBefore(target_78.getAnOperand().(VariableAccess).getLocation())
}

predicate func_12(Variable vj_360, Variable vnext_367, VariableAccess target_12) {
		target_12.getTarget()=vnext_367
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_360
}

predicate func_13(Parameter vdec_358, Variable vnext_367, Variable vcode_lengths_371, VariableAccess target_13) {
		target_13.getTarget()=vnext_367
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadHuffmanCode")
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdec_358
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcode_lengths_371
}

predicate func_14(Variable vnext_367, VariableAccess target_14) {
		target_14.getTarget()=vnext_367
}

predicate func_15(Variable vnext_367, VariableAccess target_15) {
		target_15.getTarget()=vnext_367
}

predicate func_16(Variable vnext_367, VariableAccess target_16) {
		target_16.getTarget()=vnext_367
}

predicate func_17(Variable vcode_lengths_371, VariableAccess target_17) {
		target_17.getTarget()=vcode_lengths_371
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("WebPSafeFree")
}

predicate func_18(Variable vhuffman_tables_366, VariableAccess target_18) {
		target_18.getTarget()=vhuffman_tables_366
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("WebPSafeFree")
}

predicate func_19(Variable vnum_htree_groups_limit_369, VariableAccess target_19) {
		target_19.getTarget()=vnum_htree_groups_limit_369
		and target_19.getParent().(AssignExpr).getLValue() = target_19
		and target_19.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_19.getParent().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1000"
		and target_19.getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
}

predicate func_20(Function func, Literal target_20) {
		target_20.getValue()="1000"
		and not target_20.getValue()="0"
		and target_20.getParent().(GTExpr).getParent().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_20.getEnclosingFunction() = func
}

/*predicate func_21(Function func, Literal target_21) {
		target_21.getValue()="1000"
		and not target_21.getValue()="0"
		and target_21.getParent().(ConditionalExpr).getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_21.getParent().(ConditionalExpr).getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
		and target_21.getEnclosingFunction() = func
}

*/
predicate func_22(Parameter vxsize_358, VariableAccess target_22) {
		target_22.getTarget()=vxsize_358
}

predicate func_23(Parameter vysize_358, VariableAccess target_23) {
		target_23.getTarget()=vysize_358
}

predicate func_24(Variable vi_360, Variable vnum_htree_groups_368, ExprStmt target_88, VariableAccess target_24) {
		target_24.getTarget()=vnum_htree_groups_368
		and target_24.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vi_360
		and target_88.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_24.getLocation())
}

/*predicate func_25(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, BlockStmt target_92, ExprStmt target_93, RelationalOperation target_90, VariableAccess target_25) {
		target_25.getTarget()=vnum_htree_groups_368
		and target_25.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_25.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_92
		and target_25.getLocation().isBefore(target_93.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_90.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_25.getParent().(NEExpr).getAnOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_26(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, BlockStmt target_92, VariableAccess target_26) {
		target_26.getTarget()=vnum_htree_groups_limit_369
		and target_26.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_26.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_92
}

*/
/*predicate func_27(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, EqualityOperation target_78, ExprStmt target_94, VariableAccess target_27) {
		target_27.getTarget()=vnum_htree_groups_limit_369
		and target_27.getParent().(AssignExpr).getLValue() = target_27
		and target_27.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_78.getAnOperand().(VariableAccess).getLocation().isBefore(target_27.getParent().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_27.getParent().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_94.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
/*predicate func_28(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, EqualityOperation target_78, ExprStmt target_94, VariableAccess target_28) {
		target_28.getTarget()=vnum_htree_groups_368
		and target_28.getParent().(AssignExpr).getRValue() = target_28
		and target_28.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_78.getAnOperand().(VariableAccess).getLocation().isBefore(target_28.getLocation())
		and target_28.getLocation().isBefore(target_94.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
predicate func_29(Variable vhuffman_tables_366, VariableAccess target_29) {
		target_29.getTarget()=vhuffman_tables_366
		and target_29.getParent().(AssignExpr).getLValue() = target_29
		and target_29.getParent().(AssignExpr).getRValue() instanceof Literal
}

predicate func_32(Function func) {
	exists(AssignExpr target_32 |
		target_32.getLValue().(VariableAccess).getType().hasName("int *")
		and target_32.getRValue().(FunctionCall).getTarget().hasName("WebPSafeMalloc")
		and target_32.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("int")
		and target_32.getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
		and target_32.getEnclosingFunction() = func)
}

predicate func_33(Parameter vdec_358, LogicalOrExpr target_84, NotExpr target_95, ExprStmt target_96) {
	exists(IfStmt target_33 |
		target_33.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int *")
		and target_33.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_33.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_33.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="Error"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_33
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_84
		and target_95.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_96.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_34(Parameter vdec_358, NotExpr target_95, ExprStmt target_96) {
	exists(AssignExpr target_34 |
		target_34.getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_34.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_95.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_34.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_34.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_96.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_35(EqualityOperation target_78, Function func) {
	exists(GotoStmt target_35 |
		target_35.toString() = "goto ..."
		and target_35.getName() ="Error"
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_35
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_78
		and target_35.getEnclosingFunction() = func)
}

*/
predicate func_36(Function func) {
	exists(FunctionCall target_36 |
		target_36.getTarget().hasName("memset")
		and target_36.getArgument(0).(VariableAccess).getType().hasName("int *")
		and target_36.getArgument(1).(HexLiteral).getValue()="255"
		and target_36.getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_36.getArgument(2).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
		and target_36.getEnclosingFunction() = func)
}

predicate func_37(Function func) {
	exists(CommaExpr target_37 |
		target_37.getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_37.getLeftOperand().(AssignExpr).getRValue() instanceof Literal
		and target_37.getRightOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_37.getRightOperand().(AssignExpr).getRValue() instanceof Literal
		and target_37.getEnclosingFunction() = func)
}

predicate func_38(BlockStmt target_92, Function func) {
	exists(EqualityOperation target_38 |
		target_38.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("int *")
		and target_38.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_38.getParent().(IfStmt).getThen()=target_92
		and target_38.getEnclosingFunction() = func)
}

predicate func_39(Variable vnum_htree_groups_368, EqualityOperation target_78, LogicalOrExpr target_84, ExprStmt target_88) {
	exists(ExprStmt target_39 |
		target_39.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("int *")
		and target_39.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_39.getParent().(IfStmt).getCondition()=target_78
		and target_84.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_39.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_39.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_88.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_40(Function func) {
	exists(PointerDereferenceExpr target_40 |
		target_40.getOperand().(VariableAccess).getType().hasName("int *")
		and target_40.getParent().(AssignExpr).getLValue() = target_40
		and target_40.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_40.getParent().(AssignExpr).getRValue().(ConditionalExpr).getThen() instanceof Literal
		and target_40.getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
		and target_40.getEnclosingFunction() = func)
}

*/
/*predicate func_41(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, LogicalOrExpr target_84, ExprStmt target_88) {
	exists(PostfixIncrExpr target_41 |
		target_41.getOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_41.getParent().(AssignExpr).getRValue() = target_41
		and target_41.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_84.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
		and target_41.getOperand().(VariableAccess).getLocation().isBefore(target_88.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_42(Variable vi_360, Variable vhuffman_image_364, ExprStmt target_97) {
	exists(ExprStmt target_42 |
		target_42.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhuffman_image_364
		and target_42.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_360
		and target_42.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("int *")
		and target_42.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_97.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_43(Function func) {
	exists(FunctionCall target_43 |
		target_43.getTarget().hasName("WebPSafeMalloc")
		and target_43.getArgument(0).(VariableAccess).getType().hasName("int")
		and target_43.getArgument(1).(SizeofExprOperator).getValue()="4"
		and target_43.getEnclosingFunction() = func)
}

predicate func_44(Parameter vdec_358, LogicalOrExpr target_84, ExprStmt target_98) {
	exists(IfStmt target_44 |
		target_44.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("HuffmanCode *")
		and target_44.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_44.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_44.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_44.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="Error"
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_44
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_84
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_44.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_45(Parameter vdec_358, ExprStmt target_98) {
	exists(AssignExpr target_45 |
		target_45.getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_45.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_45.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_46(Variable vi_360, Variable vj_360, Variable vnext_367, Variable vhtree_group_441, Variable vsize_443, Variable vtotal_size_444, Variable vis_trivial_literal_445, Variable vmax_bits_446, AddressOfExpr target_99, LogicalAndExpr target_100, ExprStmt target_101, LogicalAndExpr target_102, ExprStmt target_103, Function func) {
	exists(ForStmt target_46 |
		target_46.getInitialization() instanceof ExprStmt
		and target_46.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_46.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_46.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_360
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_360
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_360
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_360
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("HuffmanCode *")
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_443
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadHuffmanCode")
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_443
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="Error"
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_trivial_literal_445
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vtotal_size_444
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bits"
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getType().hasName("HuffmanCode *")
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsize_443
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(8).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_360
		and target_46.getStmt().(BlockStmt).getStmt(9).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_46.getStmt().(BlockStmt).getStmt(9).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnext_367
		and target_46.getStmt().(BlockStmt).getStmt(9).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("HuffmanCode *")
		and target_46.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_trivial_literal"
		and target_46.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtree_group_441
		and target_46.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vis_trivial_literal_445
		and target_46.getStmt().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_trivial_code"
		and target_46.getStmt().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtree_group_441
		and target_46.getStmt().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_46.getStmt().(BlockStmt).getStmt(12).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_trivial_literal_445
		and target_46.getStmt().(BlockStmt).getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="literal_arb"
		and target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="use_packed_table"
		and target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtree_group_441
		and target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_trivial_code"
		and target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_bits_446
		and target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="6"
		and target_46.getStmt().(BlockStmt).getStmt(14).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="use_packed_table"
		and target_46.getStmt().(BlockStmt).getStmt(14).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtree_group_441
		and target_46.getStmt().(BlockStmt).getStmt(14).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BuildPackedTable")
		and target_46.getStmt().(BlockStmt).getStmt(14).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhtree_group_441
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_46 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_46)
		and target_99.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_46.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_100.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_46.getStmt().(BlockStmt).getStmt(9).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_101.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_46.getStmt().(BlockStmt).getStmt(8).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_102.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_103.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_46.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_49(Variable vi_360, Variable vhtree_groups_365, ExprStmt target_104, EqualityOperation target_85, LogicalOrExpr target_105, ExprStmt target_63) {
	exists(ConditionalExpr target_49 |
		target_49.getCondition().(VariableAccess).getType().hasName("int")
		and target_49.getThen().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("HTreeGroup")
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhtree_groups_365
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int *")
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vi_360
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int *")
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_360
		and target_104.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(VariableAccess).getLocation())
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(VariableAccess).getLocation().isBefore(target_85.getAnOperand().(VariableAccess).getLocation())
		and target_105.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_49.getElse().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_63.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_51(Function func) {
	exists(EqualityOperation target_51 |
		target_51.getAnOperand().(VariableAccess).getType().hasName("int *")
		and target_51.getAnOperand().(Literal).getValue()="0"
		and target_51.getEnclosingFunction() = func)
}

*/
/*predicate func_53(Variable vi_360, EqualityOperation target_85) {
	exists(ArrayExpr target_53 |
		target_53.getArrayBase().(VariableAccess).getType().hasName("int *")
		and target_53.getArrayOffset().(VariableAccess).getTarget()=vi_360
		and target_53.getArrayOffset().(VariableAccess).getLocation().isBefore(target_85.getAnOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_54(Variable vnext_367, ExprStmt target_101) {
	exists(IfStmt target_54 |
		target_54.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_54.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnext_367
		and target_54.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("HuffmanCode *")
		and target_54.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_101.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_57(Function func) {
	exists(IfStmt target_57 |
		target_57.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_57.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_57.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_57.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_57 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_57))
}

predicate func_59(Parameter vdec_358, Variable vhtree_groups_365, Variable vhuffman_tables_366, Variable vcode_lengths_371, IfStmt target_59) {
		target_59.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhtree_groups_365
		and target_59.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_59.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcode_lengths_371
		and target_59.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_59.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhuffman_tables_366
		and target_59.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_59.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_59.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_59.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_59.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="Error"
}

predicate func_60(Variable vhuffman_tables_366, Variable vnext_367, ExprStmt target_60) {
		target_60.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnext_367
		and target_60.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vhuffman_tables_366
}

predicate func_61(Variable vi_360, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_360
		and target_61.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_62(Variable vhuffman_tables_366, EqualityOperation target_78, ExprStmt target_62) {
		target_62.getExpr().(FunctionCall).getTarget().hasName("WebPSafeFree")
		and target_62.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhuffman_tables_366
		and target_62.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_78
}

predicate func_63(Variable vhtree_groups_365, EqualityOperation target_78, ExprStmt target_63) {
		target_63.getExpr().(FunctionCall).getTarget().hasName("VP8LHtreeGroupsFree")
		and target_63.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhtree_groups_365
		and target_63.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_78
}

predicate func_64(Variable vhuffman_image_364, Function func, ExprStmt target_64) {
		target_64.getExpr().(FunctionCall).getTarget().hasName("WebPSafeFree")
		and target_64.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhuffman_image_364
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_64
}

predicate func_65(Parameter vdec_358, VariableAccess target_65) {
		target_65.getTarget()=vdec_358
}

predicate func_66(Variable vi_360, Variable vhtree_groups_365, VariableAccess target_66) {
		target_66.getTarget()=vi_360
		and target_66.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhtree_groups_365
}

predicate func_69(Parameter vdec_358, VariableAccess target_69) {
		target_69.getTarget()=vdec_358
}

predicate func_71(Variable vi_360, Variable vnum_htree_groups_368, VariableAccess target_71) {
		target_71.getTarget()=vi_360
		and target_71.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
}

predicate func_74(Parameter vxsize_358, Parameter vysize_358, RelationalOperation target_74) {
		 (target_74 instanceof GTExpr or target_74 instanceof LTExpr)
		and target_74.getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vxsize_358
		and target_74.getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vysize_358
		and target_74.getLesserOperand() instanceof Literal
}

predicate func_75(Parameter vxsize_358, Parameter vysize_358, MulExpr target_75) {
		target_75.getLeftOperand().(VariableAccess).getTarget()=vxsize_358
		and target_75.getRightOperand().(VariableAccess).getTarget()=vysize_358
}

predicate func_76(Parameter vdec_358, Variable vbr_tmp_362, AssignExpr target_76) {
		target_76.getLValue().(VariableAccess).getTarget()=vbr_tmp_362
		and target_76.getRValue().(PointerFieldAccess).getTarget().getName()="br_"
		and target_76.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
}

predicate func_77(Variable vi_360, Variable vj_360, Variable vbr_tmp_362, Variable vhtree_groups_365, Variable vhuffman_tables_366, Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, Variable vtable_size_372, Variable vhtree_group_441, Variable vis_trivial_literal_445, Function func, DoStmt target_77) {
		target_77.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_360
		and target_77.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_77.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhuffman_tables_366
		and target_77.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WebPSafeMalloc")
		and target_77.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_77.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtable_size_372
		and target_77.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
		and target_77.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhtree_groups_365
		and target_77.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("VP8LHtreeGroupsNew")
		and target_77.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_77.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_77.getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getInitialization() instanceof ExprStmt
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_360
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_360
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_360
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(6).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_360
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_trivial_literal"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vis_trivial_literal_445
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_trivial_code"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(9).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_trivial_literal_445
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="use_packed_table"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(11).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="use_packed_table"
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(11).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtree_group_441
		and target_77.getStmt().(BlockStmt).getStmt(4).(ForStmt).getStmt().(BlockStmt).getStmt(11).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BuildPackedTable")
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhuffman_tables_366
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhtree_groups_365
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="br_"
		and target_77.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbr_tmp_362
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_77
}

predicate func_78(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, EqualityOperation target_78) {
		target_78.getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_78.getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
}

/*predicate func_79(Variable vhtree_groups_365, AssignExpr target_79) {
		target_79.getLValue().(VariableAccess).getTarget()=vhtree_groups_365
		and target_79.getRValue() instanceof Literal
}

*/
/*predicate func_80(Parameter vdec_358, Variable vbr_tmp_362, AssignExpr target_80) {
		target_80.getLValue().(PointerFieldAccess).getTarget().getName()="br_"
		and target_80.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
		and target_80.getRValue().(VariableAccess).getTarget()=vbr_tmp_362
}

*/
predicate func_81(Variable vhtree_groups_365, FunctionCall target_81) {
		target_81.getTarget().hasName("VP8LHtreeGroupsFree")
		and target_81.getArgument(0).(VariableAccess).getTarget()=vhtree_groups_365
}

predicate func_82(Function func, ReturnStmt target_82) {
		target_82.getExpr() instanceof Literal
		and target_82.getEnclosingFunction() = func
}

predicate func_83(Variable vnum_htree_groups_368, BlockStmt target_83) {
		target_83.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_83.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_84(Parameter vxsize_358, Parameter vysize_358, Variable vnum_htree_groups_368, LogicalOrExpr target_84) {
		target_84.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_84.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1000"
		and target_84.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_84.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vxsize_358
		and target_84.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vysize_358
}

predicate func_85(Variable vi_360, Variable vnum_htree_groups_368, EqualityOperation target_85) {
		target_85.getAnOperand().(VariableAccess).getTarget()=vi_360
		and target_85.getAnOperand().(VariableAccess).getTarget()=vnum_htree_groups_368
}

predicate func_86(Variable vnum_htree_groups_limit_369, ExprStmt target_86) {
		target_86.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_86.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_86.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen() instanceof Literal
		and target_86.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
}

predicate func_87(Variable vnum_htree_groups_limit_369, Variable vtable_size_372, MulExpr target_87) {
		target_87.getLeftOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_87.getRightOperand().(VariableAccess).getTarget()=vtable_size_372
}

predicate func_88(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, ExprStmt target_88) {
		target_88.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_88.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
}

predicate func_89(Variable vhtree_groups_365, Variable vnum_htree_groups_limit_369, ExprStmt target_89) {
		target_89.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhtree_groups_365
		and target_89.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("VP8LHtreeGroupsNew")
		and target_89.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnum_htree_groups_limit_369
}

predicate func_90(Variable vi_360, Variable vnum_htree_groups_limit_369, RelationalOperation target_90) {
		 (target_90 instanceof GTExpr or target_90 instanceof LTExpr)
		and target_90.getLesserOperand().(VariableAccess).getTarget()=vi_360
		and target_90.getGreaterOperand().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
}

predicate func_91(Variable vj_360, Variable vnext_367, BlockStmt target_91) {
		target_91.getStmt(6).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_360
		and target_91.getStmt(6).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_91.getStmt(6).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_360
		and target_91.getStmt(6).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_91.getStmt(6).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_360
		and target_91.getStmt(6).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_360
		and target_91.getStmt(6).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnext_367
		and target_91.getStmt(6).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vj_360
		and target_91.getStmt(6).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_91.getStmt(6).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_92(Variable vhuffman_tables_366, Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, BlockStmt target_92) {
		target_92.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_92.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
		and target_92.getStmt(1) instanceof ExprStmt
		and target_92.getStmt(2) instanceof ExprStmt
		and target_92.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhuffman_tables_366
		and target_92.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_93(Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, ExprStmt target_93) {
		target_93.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_htree_groups_limit_369
		and target_93.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
}

predicate func_94(Variable vnum_htree_groups_368, ExprStmt target_94) {
		target_94.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_htree_groups_"
		and target_94.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_htree_groups_368
}

predicate func_95(Parameter vdec_358, Variable vhuffman_image_364, NotExpr target_95) {
		target_95.getOperand().(FunctionCall).getTarget().hasName("DecodeImageStream")
		and target_95.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_95.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdec_358
		and target_95.getOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhuffman_image_364
}

predicate func_96(Parameter vdec_358, ExprStmt target_96) {
		target_96.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status_"
		and target_96.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_358
}

predicate func_97(Variable vhuffman_image_364, ExprStmt target_97) {
		target_97.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="huffman_image_"
		and target_97.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vhuffman_image_364
}

predicate func_98(Parameter vdec_358, Variable vnext_367, Variable vcode_lengths_371, Variable vsize_443, ExprStmt target_98) {
		target_98.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_443
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadHuffmanCode")
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdec_358
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcode_lengths_371
		and target_98.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnext_367
}

predicate func_99(Variable vi_360, Variable vhtree_groups_365, AddressOfExpr target_99) {
		target_99.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhtree_groups_365
		and target_99.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_360
}

predicate func_100(Variable vj_360, LogicalAndExpr target_100) {
		target_100.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vj_360
		and target_100.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_100.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_101(Variable vj_360, Variable vnext_367, ExprStmt target_101) {
		target_101.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_360
		and target_101.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnext_367
}

predicate func_102(Variable vtotal_size_444, LogicalAndExpr target_102) {
		target_102.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtotal_size_444
		and target_102.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_102.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="value"
		and target_102.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_102.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
}

predicate func_103(Variable vmax_bits_446, ExprStmt target_103) {
		target_103.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vmax_bits_446
}

predicate func_104(Variable vi_360, Variable vhuffman_image_364, ExprStmt target_104) {
		target_104.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhuffman_image_364
		and target_104.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_360
}

predicate func_105(Variable vhtree_groups_365, Variable vhuffman_tables_366, Variable vcode_lengths_371, LogicalOrExpr target_105) {
		target_105.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhtree_groups_365
		and target_105.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_105.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcode_lengths_371
		and target_105.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_105.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhuffman_tables_366
		and target_105.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdec_358, Parameter vxsize_358, Parameter vysize_358, Variable vi_360, Variable vj_360, Variable vbr_tmp_362, Variable vhuffman_image_364, Variable vhtree_groups_365, Variable vhuffman_tables_366, Variable vnext_367, Variable vnum_htree_groups_368, Variable vnum_htree_groups_limit_369, Variable vcode_lengths_371, Variable vtable_size_372, Variable vhtree_group_441, Variable vsize_443, Variable vtotal_size_444, Variable vis_trivial_literal_445, Variable vmax_bits_446, Initializer target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, Literal target_20, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_29, IfStmt target_59, ExprStmt target_60, ExprStmt target_61, ExprStmt target_62, ExprStmt target_63, ExprStmt target_64, VariableAccess target_65, VariableAccess target_66, VariableAccess target_69, VariableAccess target_71, RelationalOperation target_74, MulExpr target_75, AssignExpr target_76, DoStmt target_77, EqualityOperation target_78, FunctionCall target_81, ReturnStmt target_82, BlockStmt target_83, LogicalOrExpr target_84, EqualityOperation target_85, ExprStmt target_86, MulExpr target_87, ExprStmt target_88, ExprStmt target_89, RelationalOperation target_90, BlockStmt target_91, BlockStmt target_92, ExprStmt target_93, ExprStmt target_94, NotExpr target_95, ExprStmt target_96, ExprStmt target_97, ExprStmt target_98, AddressOfExpr target_99, LogicalAndExpr target_100, ExprStmt target_101, LogicalAndExpr target_102, ExprStmt target_103, ExprStmt target_104, LogicalOrExpr target_105
where
func_0(func, target_0)
and func_1(vnum_htree_groups_368, target_83, target_1)
and func_2(vnum_htree_groups_368, target_2)
and func_3(vnum_htree_groups_368, target_3)
and func_4(vnum_htree_groups_368, target_4)
and func_5(vxsize_358, target_84, target_5)
and func_6(vysize_358, target_84, target_6)
and func_9(vnum_htree_groups_limit_369, target_88, target_89, target_9)
and func_10(vnum_htree_groups_limit_369, target_87, target_90, target_10)
and func_11(vi_360, vnum_htree_groups_limit_369, target_91, target_89, target_78, target_11)
and func_12(vj_360, vnext_367, target_12)
and func_13(vdec_358, vnext_367, vcode_lengths_371, target_13)
and func_14(vnext_367, target_14)
and func_15(vnext_367, target_15)
and func_16(vnext_367, target_16)
and func_17(vcode_lengths_371, target_17)
and func_18(vhuffman_tables_366, target_18)
and func_19(vnum_htree_groups_limit_369, target_19)
and func_20(func, target_20)
and func_22(vxsize_358, target_22)
and func_23(vysize_358, target_23)
and func_24(vi_360, vnum_htree_groups_368, target_88, target_24)
and func_29(vhuffman_tables_366, target_29)
and not func_32(func)
and not func_33(vdec_358, target_84, target_95, target_96)
and not func_36(func)
and not func_37(func)
and not func_38(target_92, func)
and not func_39(vnum_htree_groups_368, target_78, target_84, target_88)
and not func_42(vi_360, vhuffman_image_364, target_97)
and not func_43(func)
and not func_44(vdec_358, target_84, target_98)
and not func_46(vi_360, vj_360, vnext_367, vhtree_group_441, vsize_443, vtotal_size_444, vis_trivial_literal_445, vmax_bits_446, target_99, target_100, target_101, target_102, target_103, func)
and not func_49(vi_360, vhtree_groups_365, target_104, target_85, target_105, target_63)
and not func_57(func)
and func_59(vdec_358, vhtree_groups_365, vhuffman_tables_366, vcode_lengths_371, target_59)
and func_60(vhuffman_tables_366, vnext_367, target_60)
and func_61(vi_360, target_61)
and func_62(vhuffman_tables_366, target_78, target_62)
and func_63(vhtree_groups_365, target_78, target_63)
and func_64(vhuffman_image_364, func, target_64)
and func_65(vdec_358, target_65)
and func_66(vi_360, vhtree_groups_365, target_66)
and func_69(vdec_358, target_69)
and func_71(vi_360, vnum_htree_groups_368, target_71)
and func_74(vxsize_358, vysize_358, target_74)
and func_75(vxsize_358, vysize_358, target_75)
and func_76(vdec_358, vbr_tmp_362, target_76)
and func_77(vi_360, vj_360, vbr_tmp_362, vhtree_groups_365, vhuffman_tables_366, vnum_htree_groups_368, vnum_htree_groups_limit_369, vtable_size_372, vhtree_group_441, vis_trivial_literal_445, func, target_77)
and func_78(vnum_htree_groups_368, vnum_htree_groups_limit_369, target_78)
and func_81(vhtree_groups_365, target_81)
and func_82(func, target_82)
and func_83(vnum_htree_groups_368, target_83)
and func_84(vxsize_358, vysize_358, vnum_htree_groups_368, target_84)
and func_85(vi_360, vnum_htree_groups_368, target_85)
and func_86(vnum_htree_groups_limit_369, target_86)
and func_87(vnum_htree_groups_limit_369, vtable_size_372, target_87)
and func_88(vnum_htree_groups_368, vnum_htree_groups_limit_369, target_88)
and func_89(vhtree_groups_365, vnum_htree_groups_limit_369, target_89)
and func_90(vi_360, vnum_htree_groups_limit_369, target_90)
and func_91(vj_360, vnext_367, target_91)
and func_92(vhuffman_tables_366, vnum_htree_groups_368, vnum_htree_groups_limit_369, target_92)
and func_93(vnum_htree_groups_368, vnum_htree_groups_limit_369, target_93)
and func_94(vnum_htree_groups_368, target_94)
and func_95(vdec_358, vhuffman_image_364, target_95)
and func_96(vdec_358, target_96)
and func_97(vhuffman_image_364, target_97)
and func_98(vdec_358, vnext_367, vcode_lengths_371, vsize_443, target_98)
and func_99(vi_360, vhtree_groups_365, target_99)
and func_100(vj_360, target_100)
and func_101(vj_360, vnext_367, target_101)
and func_102(vtotal_size_444, target_102)
and func_103(vmax_bits_446, target_103)
and func_104(vi_360, vhuffman_image_364, target_104)
and func_105(vhtree_groups_365, vhuffman_tables_366, vcode_lengths_371, target_105)
and vdec_358.getType().hasName("VP8LDecoder *const")
and vxsize_358.getType().hasName("int")
and vysize_358.getType().hasName("int")
and vi_360.getType().hasName("int")
and vj_360.getType().hasName("int")
and vbr_tmp_362.getType().hasName("VP8LBitReader")
and vhuffman_image_364.getType().hasName("uint32_t *")
and vhtree_groups_365.getType().hasName("HTreeGroup *")
and vhuffman_tables_366.getType().hasName("HuffmanCode *")
and vnext_367.getType().hasName("HuffmanCode *")
and vnum_htree_groups_368.getType().hasName("int")
and vnum_htree_groups_limit_369.getType().hasName("int")
and vcode_lengths_371.getType().hasName("int *")
and vtable_size_372.getType().hasName("const int")
and vhtree_group_441.getType().hasName("HTreeGroup *const")
and vsize_443.getType().hasName("int")
and vtotal_size_444.getType().hasName("int")
and vis_trivial_literal_445.getType().hasName("int")
and vmax_bits_446.getType().hasName("int")
and vdec_358.getParentScope+() = func
and vxsize_358.getParentScope+() = func
and vysize_358.getParentScope+() = func
and vi_360.getParentScope+() = func
and vj_360.getParentScope+() = func
and vbr_tmp_362.getParentScope+() = func
and vhuffman_image_364.getParentScope+() = func
and vhtree_groups_365.getParentScope+() = func
and vhuffman_tables_366.getParentScope+() = func
and vnext_367.getParentScope+() = func
and vnum_htree_groups_368.getParentScope+() = func
and vnum_htree_groups_limit_369.getParentScope+() = func
and vcode_lengths_371.getParentScope+() = func
and vtable_size_372.getParentScope+() = func
and vhtree_group_441.getParentScope+() = func
and vsize_443.getParentScope+() = func
and vtotal_size_444.getParentScope+() = func
and vis_trivial_literal_445.getParentScope+() = func
and vmax_bits_446.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
