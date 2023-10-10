/**
 * @name libtiff-07d79fcac2ead271b60e32aeb80f7b4f3be9ac8c-computeInputPixelOffsets
 * @id cpp/libtiff/07d79fcac2ead271b60e32aeb80f7b4f3be9ac8c/computeInputPixelOffsets
 * @description libtiff-07d79fcac2ead271b60e32aeb80f7b4f3be9ac8c-tools/tiffcrop.c-computeInputPixelOffsets CVE-2022-2867
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcrop_width_5136, BlockStmt target_43, ExprStmt target_44, RelationalOperation target_45, VariableAccess target_0) {
		target_0.getTarget()=vcrop_width_5136
		and target_0.getParent().(LEExpr).getGreaterOperand() instanceof Literal
		and target_0.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_43
		and target_44.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_45.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vcrop_length_5136, BlockStmt target_46, ExprStmt target_47, RelationalOperation target_48, VariableAccess target_1) {
		target_1.getTarget()=vcrop_length_5136
		and target_1.getParent().(LEExpr).getGreaterOperand() instanceof Literal
		and target_1.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_46
		and target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLocation())
		and target_1.getLocation().isBefore(target_48.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vx1_5138, ExprStmt target_49, ExprStmt target_50, ExprStmt target_29) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vx1_5138
		and target_2.getLesserOperand().(VariableAccess).getType().hasName("uint32_t")
		and target_2.getParent().(IfStmt).getThen()=target_49
		and target_50.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(RelationalOperation target_41, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32_t")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint32_t")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Variable vx1_5138, Variable vx2_5138, RelationalOperation target_41, ExprStmt target_30) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx1_5138
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vx2_5138
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_30.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_8(Variable vx2_5138, RelationalOperation target_41, ExprStmt target_51, RelationalOperation target_26) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx2_5138
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint32_t")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_51.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_26.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vy1_5138, Variable vy2_5138, ExprStmt target_31, ExprStmt target_52) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vy1_5138
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vy2_5138
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_9.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_31.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_10(Variable vy1_5138, RelationalOperation target_26, ExprStmt target_53) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32_t")
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vy1_5138
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_53.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_11(Variable vy1_5138, Variable vy2_5138, RelationalOperation target_26, RelationalOperation target_42) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_5138
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vy2_5138
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_42.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_12(Variable vy2_5138, RelationalOperation target_26, RelationalOperation target_28) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy2_5138
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint32_t")
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_28.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vimage_5126, Variable vx1_5138, ExprStmt target_54, ExprStmt target_55, ExprStmt target_29) {
	exists(RelationalOperation target_13 |
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vx1_5138
		and target_13.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_13.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_13.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_13.getParent().(IfStmt).getThen()=target_54
		and target_55.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_14(Parameter vimage_5126, EqualityOperation target_56, RelationalOperation target_26) {
	exists(AssignExpr target_14 |
		target_14.getLValue() instanceof ValueFieldAccess
		and target_14.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_14.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_14.getRValue().(SubExpr).getRightOperand() instanceof Literal
		and target_56.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Variable vx1_5138, BlockStmt target_43) {
	exists(RelationalOperation target_15 |
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=vx1_5138
		and target_15.getLesserOperand() instanceof Literal
		and target_15.getParent().(IfStmt).getThen()=target_43)
}

predicate func_16(Variable vx2_5138, RelationalOperation target_28) {
	exists(IfStmt target_16 |
		target_16.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vx2_5138
		and target_16.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_16.getThen() instanceof ExprStmt
		and target_16.getParent().(IfStmt).getCondition()=target_28)
}

predicate func_17(Parameter vimage_5126, Variable vy1_5138, ExprStmt target_57, RelationalOperation target_28, ExprStmt target_31) {
	exists(IfStmt target_17 |
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vy1_5138
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_17.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vy1_5138
		and target_17.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_17.getElse().(IfStmt).getThen() instanceof ExprStmt
		and target_57.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_31.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_18(Parameter vimage_5126, RelationalOperation target_28) {
	exists(AssignExpr target_18 |
		target_18.getLValue() instanceof ValueFieldAccess
		and target_18.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_18.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_18.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_18.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_19(Parameter vcrop_5126, Parameter vimage_5126, Variable vi_5137, Variable vy2_5138, ArrayExpr target_58, ArrayExpr target_59, RelationalOperation target_28, ExprStmt target_32) {
	exists(IfStmt target_19 |
		target_19.getCondition() instanceof RelationalOperation
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y2"
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_19.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vy2_5138
		and target_19.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_19.getElse().(IfStmt).getThen() instanceof ExprStmt
		and target_58.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_59.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_28.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_19.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_20(Variable vstartx_5134, Variable vendx_5134, ExprStmt target_44, Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vendx_5134
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_20.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstartx_5134
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeInputPixelOffsets"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid left/right margins and /or image crop width requested"
		and target_20.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_20 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_20)
		and target_44.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_20.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_21(Variable vendx_5134, Variable vcrop_width_5136, BlockStmt target_43, ExprStmt target_44) {
	exists(AddExpr target_21 |
		target_21.getAnOperand().(VariableAccess).getTarget()=vendx_5134
		and target_21.getAnOperand().(Literal).getValue()="1"
		and target_21.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vcrop_width_5136
		and target_21.getParent().(LEExpr).getGreaterOperand() instanceof Literal
		and target_21.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_43
		and target_44.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_21.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_23(Variable vendy_5135, Variable vcrop_length_5136, BlockStmt target_46, ExprStmt target_47) {
	exists(AddExpr target_23 |
		target_23.getAnOperand().(VariableAccess).getTarget()=vendy_5135
		and target_23.getAnOperand().(Literal).getValue()="1"
		and target_23.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vcrop_length_5136
		and target_23.getParent().(LEExpr).getGreaterOperand() instanceof Literal
		and target_23.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_46
		and target_47.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_25(Parameter vcrop_5126, Variable vi_5137, ValueFieldAccess target_25) {
		target_25.getTarget().getName()="x1"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_26(Parameter vimage_5126, Variable vx2_5138, RelationalOperation target_26) {
		 (target_26 instanceof GTExpr or target_26 instanceof LTExpr)
		and target_26.getGreaterOperand().(VariableAccess).getTarget()=vx2_5138
		and target_26.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_26.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_26.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_26.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_27(Parameter vcrop_5126, Variable vi_5137, ValueFieldAccess target_27) {
		target_27.getTarget().getName()="y1"
		and target_27.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_27.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_27.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_28(Parameter vimage_5126, Variable vy2_5138, RelationalOperation target_28) {
		 (target_28 instanceof GTExpr or target_28 instanceof LTExpr)
		and target_28.getGreaterOperand().(VariableAccess).getTarget()=vy2_5138
		and target_28.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_28.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_28.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_28.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_29(Parameter vcrop_5126, Variable vi_5137, Variable vx1_5138, RelationalOperation target_41, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x1"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vx1_5138
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_29.getParent().(IfStmt).getCondition()=target_41
}

predicate func_30(Parameter vcrop_5126, Variable vi_5137, Variable vx2_5138, RelationalOperation target_26, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x2"
		and target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_30.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vx2_5138
		and target_30.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_30.getParent().(IfStmt).getCondition()=target_26
}

predicate func_31(Parameter vcrop_5126, Variable vi_5137, Variable vy1_5138, RelationalOperation target_42, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y1"
		and target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_31.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vy1_5138
		and target_31.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_31.getParent().(IfStmt).getCondition()=target_42
}

predicate func_32(Parameter vcrop_5126, Variable vi_5137, Variable vy2_5138, RelationalOperation target_28, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y2"
		and target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_32.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vy2_5138
		and target_32.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_32.getParent().(IfStmt).getCondition()=target_28
}

predicate func_33(Variable vx1_5138, ExprStmt target_49, VariableAccess target_33) {
		target_33.getTarget()=vx1_5138
		and target_33.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="1"
		and target_33.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_49
}

predicate func_36(Variable vy1_5138, ExprStmt target_54, VariableAccess target_36) {
		target_36.getTarget()=vy1_5138
		and target_36.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="1"
		and target_36.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_54
}

predicate func_41(Variable vx1_5138, ExprStmt target_49, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(VariableAccess).getTarget()=vx1_5138
		and target_41.getGreaterOperand() instanceof Literal
		and target_41.getParent().(IfStmt).getThen()=target_49
}

predicate func_42(Variable vy1_5138, ExprStmt target_54, RelationalOperation target_42) {
		 (target_42 instanceof GTExpr or target_42 instanceof LTExpr)
		and target_42.getLesserOperand().(VariableAccess).getTarget()=vy1_5138
		and target_42.getGreaterOperand() instanceof Literal
		and target_42.getParent().(IfStmt).getThen()=target_54
}

predicate func_43(BlockStmt target_43) {
		target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeInputPixelOffsets"
		and target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid left/right margins and /or image crop width requested"
		and target_43.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_44(Variable vstartx_5134, Variable vendx_5134, Variable vcrop_width_5136, ExprStmt target_44) {
		target_44.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcrop_width_5136
		and target_44.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vendx_5134
		and target_44.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstartx_5134
		and target_44.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_45(Parameter vimage_5126, Variable vcrop_width_5136, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getGreaterOperand().(VariableAccess).getTarget()=vcrop_width_5136
		and target_45.getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_45.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
}

predicate func_46(BlockStmt target_46) {
		target_46.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_46.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeInputPixelOffsets"
		and target_46.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid top/bottom margins and /or image crop length requested"
		and target_46.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_47(Variable vendy_5135, Variable vcrop_length_5136, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcrop_length_5136
		and target_47.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vendy_5135
		and target_47.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_47.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_48(Parameter vimage_5126, Variable vcrop_length_5136, RelationalOperation target_48) {
		 (target_48 instanceof GTExpr or target_48 instanceof LTExpr)
		and target_48.getGreaterOperand().(VariableAccess).getTarget()=vcrop_length_5136
		and target_48.getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_48.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
}

predicate func_49(ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_49.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_50(Parameter vcrop_5126, Variable vi_5137, Variable vx1_5138, ExprStmt target_50) {
		target_50.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx1_5138
		and target_50.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="X1"
		and target_50.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_50.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_50.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_51(Parameter vcrop_5126, Variable vi_5137, Variable vx2_5138, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx2_5138
		and target_51.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="X2"
		and target_51.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_51.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_51.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_52(Parameter vcrop_5126, Variable vi_5137, Variable vy2_5138, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy2_5138
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Y2"
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_52.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_53(Parameter vcrop_5126, Variable vi_5137, Variable vy1_5138, ExprStmt target_53) {
		target_53.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_5138
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="Y1"
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_53.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_54(ExprStmt target_54) {
		target_54.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_54.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_55(Parameter vcrop_5126, Parameter vimage_5126, Variable vi_5137, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x2"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_55.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_55.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_55.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_56(Parameter vimage_5126, EqualityOperation target_56) {
		target_56.getAnOperand().(PointerFieldAccess).getTarget().getName()="res_unit"
		and target_56.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_56.getAnOperand().(Literal).getValue()="3"
}

predicate func_57(Parameter vcrop_5126, Parameter vimage_5126, Variable vi_5137, ExprStmt target_57) {
		target_57.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y2"
		and target_57.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_57.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_57.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5137
		and target_57.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_57.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5126
		and target_57.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_58(Parameter vcrop_5126, Variable vi_5137, ArrayExpr target_58) {
		target_58.getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_58.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_58.getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

predicate func_59(Parameter vcrop_5126, Variable vi_5137, ArrayExpr target_59) {
		target_59.getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_59.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5126
		and target_59.getArrayOffset().(VariableAccess).getTarget()=vi_5137
}

from Function func, Parameter vcrop_5126, Parameter vimage_5126, Variable vstartx_5134, Variable vendx_5134, Variable vendy_5135, Variable vcrop_width_5136, Variable vcrop_length_5136, Variable vi_5137, Variable vx1_5138, Variable vx2_5138, Variable vy1_5138, Variable vy2_5138, VariableAccess target_0, VariableAccess target_1, ValueFieldAccess target_25, RelationalOperation target_26, ValueFieldAccess target_27, RelationalOperation target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32, VariableAccess target_33, VariableAccess target_36, RelationalOperation target_41, RelationalOperation target_42, BlockStmt target_43, ExprStmt target_44, RelationalOperation target_45, BlockStmt target_46, ExprStmt target_47, RelationalOperation target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ExprStmt target_52, ExprStmt target_53, ExprStmt target_54, ExprStmt target_55, EqualityOperation target_56, ExprStmt target_57, ArrayExpr target_58, ArrayExpr target_59
where
func_0(vcrop_width_5136, target_43, target_44, target_45, target_0)
and func_1(vcrop_length_5136, target_46, target_47, target_48, target_1)
and not func_2(vx1_5138, target_49, target_50, target_29)
and not func_3(target_41, func)
and not func_5(vx1_5138, vx2_5138, target_41, target_30)
and not func_8(vx2_5138, target_41, target_51, target_26)
and not func_9(vy1_5138, vy2_5138, target_31, target_52)
and not func_10(vy1_5138, target_26, target_53)
and not func_11(vy1_5138, vy2_5138, target_26, target_42)
and not func_12(vy2_5138, target_26, target_28)
and not func_13(vimage_5126, vx1_5138, target_54, target_55, target_29)
and not func_14(vimage_5126, target_56, target_26)
and not func_15(vx1_5138, target_43)
and not func_16(vx2_5138, target_28)
and not func_17(vimage_5126, vy1_5138, target_57, target_28, target_31)
and not func_19(vcrop_5126, vimage_5126, vi_5137, vy2_5138, target_58, target_59, target_28, target_32)
and not func_20(vstartx_5134, vendx_5134, target_44, func)
and not func_23(vendy_5135, vcrop_length_5136, target_46, target_47)
and func_25(vcrop_5126, vi_5137, target_25)
and func_26(vimage_5126, vx2_5138, target_26)
and func_27(vcrop_5126, vi_5137, target_27)
and func_28(vimage_5126, vy2_5138, target_28)
and func_29(vcrop_5126, vi_5137, vx1_5138, target_41, target_29)
and func_30(vcrop_5126, vi_5137, vx2_5138, target_26, target_30)
and func_31(vcrop_5126, vi_5137, vy1_5138, target_42, target_31)
and func_32(vcrop_5126, vi_5137, vy2_5138, target_28, target_32)
and func_33(vx1_5138, target_49, target_33)
and func_36(vy1_5138, target_54, target_36)
and func_41(vx1_5138, target_49, target_41)
and func_42(vy1_5138, target_54, target_42)
and func_43(target_43)
and func_44(vstartx_5134, vendx_5134, vcrop_width_5136, target_44)
and func_45(vimage_5126, vcrop_width_5136, target_45)
and func_46(target_46)
and func_47(vendy_5135, vcrop_length_5136, target_47)
and func_48(vimage_5126, vcrop_length_5136, target_48)
and func_49(target_49)
and func_50(vcrop_5126, vi_5137, vx1_5138, target_50)
and func_51(vcrop_5126, vi_5137, vx2_5138, target_51)
and func_52(vcrop_5126, vi_5137, vy2_5138, target_52)
and func_53(vcrop_5126, vi_5137, vy1_5138, target_53)
and func_54(target_54)
and func_55(vcrop_5126, vimage_5126, vi_5137, target_55)
and func_56(vimage_5126, target_56)
and func_57(vcrop_5126, vimage_5126, vi_5137, target_57)
and func_58(vcrop_5126, vi_5137, target_58)
and func_59(vcrop_5126, vi_5137, target_59)
and vcrop_5126.getType().hasName("crop_mask *")
and vimage_5126.getType().hasName("image_data *")
and vstartx_5134.getType().hasName("uint32_t")
and vendx_5134.getType().hasName("uint32_t")
and vendy_5135.getType().hasName("uint32_t")
and vcrop_width_5136.getType().hasName("uint32_t")
and vcrop_length_5136.getType().hasName("uint32_t")
and vi_5137.getType().hasName("uint32_t")
and vx1_5138.getType().hasName("uint32_t")
and vx2_5138.getType().hasName("uint32_t")
and vy1_5138.getType().hasName("uint32_t")
and vy2_5138.getType().hasName("uint32_t")
and vcrop_5126.getFunction() = func
and vimage_5126.getFunction() = func
and vstartx_5134.(LocalVariable).getFunction() = func
and vendx_5134.(LocalVariable).getFunction() = func
and vendy_5135.(LocalVariable).getFunction() = func
and vcrop_width_5136.(LocalVariable).getFunction() = func
and vcrop_length_5136.(LocalVariable).getFunction() = func
and vi_5137.(LocalVariable).getFunction() = func
and vx1_5138.(LocalVariable).getFunction() = func
and vx2_5138.(LocalVariable).getFunction() = func
and vy1_5138.(LocalVariable).getFunction() = func
and vy2_5138.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
