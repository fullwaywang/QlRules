/**
 * @name ffmpeg-fe448cd28d674c3eff3072552eae366d0b659ce9-jpeg2000_decode_tile
 * @id cpp/ffmpeg/fe448cd28d674c3eff3072552eae366d0b659ce9/jpeg2000-decode-tile
 * @description ffmpeg-fe448cd28d674c3eff3072552eae366d0b659ce9-libavcodec/jpeg2000dec.c-jpeg2000_decode_tile CVE-2013-7024
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1194, Variable vcompno_1197, Variable vy_1198, ExprStmt target_8, RelationalOperation target_9, ArrayExpr target_10, ArrayExpr target_11) {
	exists(DivExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vy_1198
		and target_0.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_0.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_11.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1194, Variable vcompno_1197, Variable vx_1198, ExprStmt target_12, AssignAddExpr target_13, ArrayExpr target_14, ExprStmt target_15, RelationalOperation target_16) {
	exists(DivExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vx_1198
		and target_1.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_1.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_1.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_1.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_16.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vs_1194, Variable vcompno_1197, Variable vy_1198, ExprStmt target_17, RelationalOperation target_18, ArrayExpr target_19, ArrayExpr target_20) {
	exists(DivExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vy_1198
		and target_2.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_2.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_2.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_2.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_20.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vs_1194, Variable vcompno_1197, Variable vx_1198, ExprStmt target_21, AssignAddExpr target_22, ArrayExpr target_23, ExprStmt target_24, RelationalOperation target_25) {
	exists(DivExpr target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vx_1198
		and target_3.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_3.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_3.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_3.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getLeftOperand().(VariableAccess).getLocation().isBefore(target_25.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vy_1198, VariableAccess target_4) {
		target_4.getTarget()=vy_1198
}

predicate func_5(Variable vx_1198, VariableAccess target_5) {
		target_5.getTarget()=vx_1198
}

predicate func_6(Variable vy_1198, VariableAccess target_6) {
		target_6.getTarget()=vy_1198
}

predicate func_7(Variable vx_1198, VariableAccess target_7) {
		target_7.getTarget()=vx_1198
}

predicate func_8(Parameter vs_1194, Variable vy_1198, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_1198
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_9(Parameter vs_1194, Variable vcompno_1197, Variable vy_1198, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vy_1198
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_9.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_9.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_10(Variable vcompno_1197, ArrayExpr target_10) {
		target_10.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_10.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_11(Variable vcompno_1197, ArrayExpr target_11) {
		target_11.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_11.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_11.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_12(Parameter vs_1194, Variable vx_1198, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_1198
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_12.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_13(Parameter vs_1194, Variable vcompno_1197, Variable vx_1198, AssignAddExpr target_13) {
		target_13.getLValue().(VariableAccess).getTarget()=vx_1198
		and target_13.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_13.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_13.getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_14(Variable vcompno_1197, ArrayExpr target_14) {
		target_14.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_14.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_15(Variable vcompno_1197, Variable vx_1198, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vx_1198
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcompno_1197
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_16(Variable vx_1198, RelationalOperation target_16) {
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getLesserOperand().(VariableAccess).getTarget()=vx_1198
		and target_16.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_17(Parameter vs_1194, Variable vy_1198, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_1198
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_18(Parameter vs_1194, Variable vcompno_1197, Variable vy_1198, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vy_1198
		and target_18.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_18.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_18.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
		and target_18.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getGreaterOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_18.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_19(Variable vcompno_1197, ArrayExpr target_19) {
		target_19.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_19.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_19.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_20(Variable vcompno_1197, ArrayExpr target_20) {
		target_20.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_20.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_20.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_21(Parameter vs_1194, Variable vx_1198, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_1198
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="coord"
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_21.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
}

predicate func_22(Parameter vs_1194, Variable vcompno_1197, Variable vx_1198, AssignAddExpr target_22) {
		target_22.getLValue().(VariableAccess).getTarget()=vx_1198
		and target_22.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_22.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1194
		and target_22.getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_23(Variable vcompno_1197, ArrayExpr target_23) {
		target_23.getArrayBase().(PointerFieldAccess).getTarget().getName()="comp"
		and target_23.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Tile *")
		and target_23.getArrayOffset().(VariableAccess).getTarget()=vcompno_1197
}

predicate func_24(Variable vcompno_1197, Variable vx_1198, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint16_t *")
		and target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16_t *")
		and target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vx_1198
		and target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcompno_1197
		and target_24.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_25(Variable vx_1198, RelationalOperation target_25) {
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getLesserOperand().(VariableAccess).getTarget()=vx_1198
		and target_25.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vs_1194, Variable vcompno_1197, Variable vx_1198, Variable vy_1198, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, ExprStmt target_8, RelationalOperation target_9, ArrayExpr target_10, ArrayExpr target_11, ExprStmt target_12, AssignAddExpr target_13, ArrayExpr target_14, ExprStmt target_15, RelationalOperation target_16, ExprStmt target_17, RelationalOperation target_18, ArrayExpr target_19, ArrayExpr target_20, ExprStmt target_21, AssignAddExpr target_22, ArrayExpr target_23, ExprStmt target_24, RelationalOperation target_25
where
not func_0(vs_1194, vcompno_1197, vy_1198, target_8, target_9, target_10, target_11)
and not func_1(vs_1194, vcompno_1197, vx_1198, target_12, target_13, target_14, target_15, target_16)
and not func_2(vs_1194, vcompno_1197, vy_1198, target_17, target_18, target_19, target_20)
and not func_3(vs_1194, vcompno_1197, vx_1198, target_21, target_22, target_23, target_24, target_25)
and func_4(vy_1198, target_4)
and func_5(vx_1198, target_5)
and func_6(vy_1198, target_6)
and func_7(vx_1198, target_7)
and func_8(vs_1194, vy_1198, target_8)
and func_9(vs_1194, vcompno_1197, vy_1198, target_9)
and func_10(vcompno_1197, target_10)
and func_11(vcompno_1197, target_11)
and func_12(vs_1194, vx_1198, target_12)
and func_13(vs_1194, vcompno_1197, vx_1198, target_13)
and func_14(vcompno_1197, target_14)
and func_15(vcompno_1197, vx_1198, target_15)
and func_16(vx_1198, target_16)
and func_17(vs_1194, vy_1198, target_17)
and func_18(vs_1194, vcompno_1197, vy_1198, target_18)
and func_19(vcompno_1197, target_19)
and func_20(vcompno_1197, target_20)
and func_21(vs_1194, vx_1198, target_21)
and func_22(vs_1194, vcompno_1197, vx_1198, target_22)
and func_23(vcompno_1197, target_23)
and func_24(vcompno_1197, vx_1198, target_24)
and func_25(vx_1198, target_25)
and vs_1194.getType().hasName("Jpeg2000DecoderContext *")
and vcompno_1197.getType().hasName("int")
and vx_1198.getType().hasName("int")
and vy_1198.getType().hasName("int")
and vs_1194.getFunction() = func
and vcompno_1197.(LocalVariable).getFunction() = func
and vx_1198.(LocalVariable).getFunction() = func
and vy_1198.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
