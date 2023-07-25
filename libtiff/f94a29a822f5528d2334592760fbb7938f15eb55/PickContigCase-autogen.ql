/**
 * @name libtiff-f94a29a822f5528d2334592760fbb7938f15eb55-PickContigCase
 * @id cpp/libtiff/f94a29a822f5528d2334592760fbb7938f15eb55/PickContigCase
 * @description libtiff-f94a29a822f5528d2334592760fbb7938f15eb55-libtiff/tif_getimage.c-PickContigCase CVE-2015-8683
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimg_2504, SwitchStmt target_17, EqualityOperation target_10) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_17.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimg_2504, ExprStmt target_18, EqualityOperation target_11) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimg_2504, ExprStmt target_19, EqualityOperation target_13) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_2.getLesserOperand().(Literal).getValue()="3"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vimg_2504, ExprStmt target_7, EqualityOperation target_12) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vimg_2504, EqualityOperation target_12, FunctionCall target_20) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("BuildMapBitdepth16To8")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("BuildMapUaToAa")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_4.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_4.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_4.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_4.getElse().(IfStmt).getThen() instanceof BlockStmt
		and target_4.getParent().(IfStmt).getCondition()=target_12
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vimg_2504, ExprStmt target_21, FunctionCall target_8) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_5.getAnOperand() instanceof FunctionCall
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vimg_2504, BlockStmt target_22, ExprStmt target_23, FunctionCall target_16) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_6.getAnOperand() instanceof FunctionCall
		and target_6.getParent().(IfStmt).getThen()=target_22
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vimg_2504, EqualityOperation target_10, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_7.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_8(Parameter vimg_2504, FunctionCall target_8) {
		target_8.getTarget().hasName("buildMap")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
}

predicate func_9(Parameter vimg_2504, FunctionCall target_9) {
		target_9.getTarget().hasName("buildMap")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof BlockStmt
}

predicate func_10(Parameter vimg_2504, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_10.getAnOperand().(Literal).getValue()="1"
		and target_10.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_11(Parameter vimg_2504, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_11.getAnOperand().(Literal).getValue()="2"
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
}

predicate func_12(Parameter vimg_2504, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_12.getAnOperand().(Literal).getValue()="1"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
}

predicate func_13(Parameter vimg_2504, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_13.getAnOperand().(Literal).getValue()="2"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
}

predicate func_14(Parameter vimg_2504, EqualityOperation target_12, BlockStmt target_14) {
		target_14.getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("BuildMapBitdepth16To8")
		and target_14.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_14.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_14.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_14.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_14.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_15(Parameter vimg_2504, FunctionCall target_15) {
		target_15.getTarget().hasName("buildMap")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof BlockStmt
}

predicate func_16(Parameter vimg_2504, BlockStmt target_22, FunctionCall target_16) {
		target_16.getTarget().hasName("buildMap")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vimg_2504
		and target_16.getParent().(IfStmt).getThen()=target_22
}

predicate func_17(Parameter vimg_2504, SwitchStmt target_17) {
		target_17.getExpr().(PointerFieldAccess).getTarget().getName()="bitspersample"
		and target_17.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_17.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="8"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof EqualityOperation
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getCondition() instanceof EqualityOperation
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("BuildMapUaToAa")
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(IfStmt).getElse() instanceof ExprStmt
}

predicate func_18(Parameter vimg_2504, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
}

predicate func_19(Parameter vimg_2504, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
}

predicate func_20(Parameter vimg_2504, FunctionCall target_20) {
		target_20.getTarget().hasName("BuildMapBitdepth16To8")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vimg_2504
}

predicate func_21(Parameter vimg_2504, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
}

predicate func_22(Parameter vimg_2504, BlockStmt target_22) {
		target_22.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bitspersample"
		and target_22.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_22.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_22.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_22.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_22.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
		and target_22.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("initCIELabConversion")
		and target_22.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimg_2504
}

predicate func_23(Parameter vimg_2504, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="contig"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="put"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_2504
}

from Function func, Parameter vimg_2504, ExprStmt target_7, FunctionCall target_8, FunctionCall target_9, EqualityOperation target_10, EqualityOperation target_11, EqualityOperation target_12, EqualityOperation target_13, BlockStmt target_14, FunctionCall target_15, FunctionCall target_16, SwitchStmt target_17, ExprStmt target_18, ExprStmt target_19, FunctionCall target_20, ExprStmt target_21, BlockStmt target_22, ExprStmt target_23
where
not func_0(vimg_2504, target_17, target_10)
and not func_1(vimg_2504, target_18, target_11)
and not func_2(vimg_2504, target_19, target_13)
and not func_3(vimg_2504, target_7, target_12)
and not func_4(vimg_2504, target_12, target_20)
and not func_5(vimg_2504, target_21, target_8)
and not func_6(vimg_2504, target_22, target_23, target_16)
and func_7(vimg_2504, target_10, target_7)
and func_8(vimg_2504, target_8)
and func_9(vimg_2504, target_9)
and func_10(vimg_2504, target_10)
and func_11(vimg_2504, target_11)
and func_12(vimg_2504, target_12)
and func_13(vimg_2504, target_13)
and func_14(vimg_2504, target_12, target_14)
and func_15(vimg_2504, target_15)
and func_16(vimg_2504, target_22, target_16)
and func_17(vimg_2504, target_17)
and func_18(vimg_2504, target_18)
and func_19(vimg_2504, target_19)
and func_20(vimg_2504, target_20)
and func_21(vimg_2504, target_21)
and func_22(vimg_2504, target_22)
and func_23(vimg_2504, target_23)
and vimg_2504.getType().hasName("TIFFRGBAImage *")
and vimg_2504.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
