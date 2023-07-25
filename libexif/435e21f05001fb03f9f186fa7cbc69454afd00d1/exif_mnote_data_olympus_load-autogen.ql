/**
 * @name libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-exif_mnote_data_olympus_load
 * @id cpp/libexif/435e21f05001fb03f9f186fa7cbc69454afd00d1/exif-mnote-data-olympus-load
 * @description libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-libexif/olympus/exif-mnote-data-olympus.c-exif_mnote_data_olympus_load CVE-2020-13112
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vo2_240, VariableAccess target_0) {
		target_0.getTarget()=vo2_240
}

predicate func_1(Variable vo2_240, ArrayExpr target_80, VariableAccess target_1) {
		target_1.getTarget()=vo2_240
		and target_1.getLocation().isBefore(target_80.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vo2_240, ExprStmt target_81, VariableAccess target_2) {
		target_2.getTarget()=vo2_240
		and target_81.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLocation())
}

predicate func_3(Variable vo2_240, VariableAccess target_3) {
		target_3.getTarget()=vo2_240
}

predicate func_4(Variable vo2_240, ArrayExpr target_82, VariableAccess target_4) {
		target_4.getTarget()=vo2_240
		and target_4.getLocation().isBefore(target_82.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_5(Parameter vbuf_size_236, Variable vo2_240, SubExpr target_83) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_5.getLesserOperand().(VariableAccess).getLocation().isBefore(target_83.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vbuf_size_236, SubExpr target_83, LogicalOrExpr target_85) {
	exists(SubExpr target_6 |
		target_6.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_6.getRightOperand() instanceof Literal
		and target_83.getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation())
		and target_6.getLeftOperand().(VariableAccess).getLocation().isBefore(target_85.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vbuf_size_236, Variable vo2_240, LogicalOrExpr target_85) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_85.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vbuf_size_236, LogicalOrExpr target_87) {
	exists(SubExpr target_8 |
		target_8.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_8.getRightOperand() instanceof Literal
		and target_8.getLeftOperand().(VariableAccess).getLocation().isBefore(target_87.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vbuf_size_236, Variable vo2_240, ExprStmt target_88) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_88.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vbuf_size_236, LogicalOrExpr target_89) {
	exists(SubExpr target_10 |
		target_10.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_10.getRightOperand() instanceof Literal
		and target_10.getLeftOperand().(VariableAccess).getLocation().isBefore(target_89.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vbuf_size_236, Variable vo2_240, LogicalOrExpr target_90, PointerArithmeticOperation target_92) {
	exists(RelationalOperation target_11 |
		 (target_11 instanceof GEExpr or target_11 instanceof LEExpr)
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_90.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_11.getLesserOperand().(VariableAccess).getLocation())
		and target_11.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_92.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_12(Parameter vbuf_size_236) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand() instanceof Literal
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236)
}

predicate func_13(Parameter vbuf_size_236, Variable vo2_240, BlockStmt target_93, ExprStmt target_94) {
	exists(RelationalOperation target_13 |
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
		and target_13.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_13.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_13.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_13.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_13.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_13.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_13.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_93
		and target_94.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_14(Parameter vbuf_size_236, Variable vo_240, LogicalOrExpr target_87) {
	exists(RelationalOperation target_14 |
		 (target_14 instanceof GEExpr or target_14 instanceof LEExpr)
		and target_14.getGreaterOperand().(VariableAccess).getTarget()=vo_240
		and target_14.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_87.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_14.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_15(Parameter vbuf_size_236) {
	exists(RelationalOperation target_15 |
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand() instanceof Literal
		and target_15.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236)
}

predicate func_16(Parameter vbuf_size_236, Variable vo_240, BlockStmt target_96, LogicalOrExpr target_97, CommaExpr target_98) {
	exists(RelationalOperation target_16 |
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vo_240
		and target_16.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_16.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_16.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_16.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_16.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_16.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_16.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_96
		and target_16.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_97.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_98.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_17(Parameter vbuf_size_236, Variable vn_238, BlockStmt target_99, LogicalOrExpr target_100, LogicalOrExpr target_101, ArrayExpr target_102, ExprStmt target_103) {
	exists(LogicalAndExpr target_17 |
		target_17.getAnOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="components"
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_17.getParent().(IfStmt).getThen()=target_99
		and target_100.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_101.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_102.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_18(Parameter vbuf_size_236, Variable vn_238, LogicalOrExpr target_100, LogicalOrExpr target_101, ExprStmt target_88) {
	exists(DivExpr target_18 |
		target_18.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_18.getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_18.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_18.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_18.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_18.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_100.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_18.getLeftOperand().(VariableAccess).getLocation())
		and target_18.getLeftOperand().(VariableAccess).getLocation().isBefore(target_101.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_88.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_19(Variable vn_238, ExprStmt target_103) {
	exists(ValueFieldAccess target_19 |
		target_19.getTarget().getName()="components"
		and target_19.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_19.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_19.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_19.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_20(Parameter ven_235, Variable vn_238, VariableAccess target_52, ExprStmt target_104, ExprStmt target_105, ExprStmt target_106) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_20.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_20.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag size overflow detected (%u * %lu)"
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_20.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="components"
		and target_20.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_20.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_20.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_20
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_104.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_105.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_20.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_21(VariableAccess target_52, Function func) {
	exists(ContinueStmt target_21 |
		target_21.toString() = "continue;"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_21
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Parameter ven_235, Parameter vbuf_size_236, Variable vs_425, Variable vdataofs_455, LogicalOrExpr target_89, ExprStmt target_29, LogicalOrExpr target_97) {
	exists(IfStmt target_22 |
		target_22.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_425
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_22.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_425
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_236
		and target_22.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_22
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_89
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_97.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_22.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_23(Parameter vbuf_size_236, Variable vdataofs_455, LogicalOrExpr target_97, LogicalOrExpr target_89) {
	exists(RelationalOperation target_23 |
		 (target_23 instanceof GEExpr or target_23 instanceof LEExpr)
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_97.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_23.getLesserOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_24(Parameter vbuf_size_236, Variable vs_425, LogicalOrExpr target_89) {
	exists(RelationalOperation target_24 |
		 (target_24 instanceof GTExpr or target_24 instanceof LTExpr)
		and target_24.getGreaterOperand().(VariableAccess).getTarget()=vs_425
		and target_24.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236)
}

*/
/*predicate func_25(Parameter vbuf_size_236, Variable vs_425, Variable vdataofs_455, BlockStmt target_107, RelationalOperation target_108, PointerArithmeticOperation target_109) {
	exists(RelationalOperation target_25 |
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_25.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_25.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_425
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_25.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_107
		and target_108.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_25.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_109.getAnOperand().(VariableAccess).getLocation().isBefore(target_25.getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_26(VariableAccess target_52, Function func, DeclStmt target_26) {
		target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Variable vdatao_240, Variable vs_425, Variable vdataofs_455, VariableAccess target_52, IfStmt target_27) {
		target_27.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_425
		and target_27.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_455
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_240
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_28(Variable vs_425, Variable vdataofs_455, AddExpr target_28) {
		target_28.getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_28.getAnOperand().(VariableAccess).getTarget()=vs_425
}

predicate func_29(Parameter ven_235, Variable vn_238, Variable vtcount_240, Variable vs_425, VariableAccess target_52, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_240
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_mem_alloc")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_425
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_30(Parameter ven_235, Variable vn_238, Variable vtcount_240, Variable vs_425, VariableAccess target_52, IfStmt target_30) {
		target_30.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_30.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_30.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_30.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_240
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Could not allocate %lu byte(s)."
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_425
		and target_30.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_31(Parameter vbuf_236, Variable vn_238, Variable vtcount_240, Variable vs_425, Variable vdataofs_455, VariableAccess target_52, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_31.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_31.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_31.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_31.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_240
		and target_31.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_31.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_31.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_425
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
}

predicate func_33(Variable vo2_240, VariableAccess target_33) {
		target_33.getTarget()=vo2_240
}

predicate func_35(Parameter vbuf_size_236, VariableAccess target_35) {
		target_35.getTarget()=vbuf_size_236
}

predicate func_37(Variable vo2_240, VariableAccess target_37) {
		target_37.getTarget()=vo2_240
}

predicate func_39(Parameter vbuf_size_236, VariableAccess target_39) {
		target_39.getTarget()=vbuf_size_236
}

predicate func_41(Variable vo2_240, VariableAccess target_41) {
		target_41.getTarget()=vo2_240
}

predicate func_44(Parameter vbuf_size_236, VariableAccess target_44) {
		target_44.getTarget()=vbuf_size_236
}

predicate func_46(Variable vo2_240, VariableAccess target_46) {
		target_46.getTarget()=vo2_240
}

predicate func_48(Parameter vbuf_size_236, VariableAccess target_48) {
		target_48.getTarget()=vbuf_size_236
}

predicate func_49(Variable vo_240, VariableAccess target_49) {
		target_49.getTarget()=vo_240
}

predicate func_51(Parameter vbuf_size_236, VariableAccess target_51) {
		target_51.getTarget()=vbuf_size_236
}

predicate func_52(Variable vs_425, BlockStmt target_99, VariableAccess target_52) {
		target_52.getTarget()=vs_425
		and target_52.getParent().(IfStmt).getThen()=target_99
}

predicate func_53(Variable vs_425, VariableAccess target_53) {
		target_53.getTarget()=vs_425
}

predicate func_54(Variable vdataofs_455, VariableAccess target_54) {
		target_54.getTarget()=vdataofs_455
}

predicate func_55(Variable vs_425, VariableAccess target_55) {
		target_55.getTarget()=vs_425
}

predicate func_56(Parameter vbuf_size_236, VariableAccess target_56) {
		target_56.getTarget()=vbuf_size_236
}

predicate func_57(Variable vo2_240, VariableAccess target_57) {
		target_57.getTarget()=vo2_240
}

predicate func_58(Variable vo2_240, VariableAccess target_58) {
		target_58.getTarget()=vo2_240
}

predicate func_59(Variable vo2_240, VariableAccess target_59) {
		target_59.getTarget()=vo2_240
}

predicate func_60(Variable vo2_240, VariableAccess target_60) {
		target_60.getTarget()=vo2_240
}

predicate func_61(Variable vo_240, VariableAccess target_61) {
		target_61.getTarget()=vo_240
}

predicate func_62(Variable vdataofs_455, VariableAccess target_62) {
		target_62.getTarget()=vdataofs_455
}

predicate func_63(Variable vo2_240, RelationalOperation target_63) {
		 (target_63 instanceof GTExpr or target_63 instanceof LTExpr)
		and target_63.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_63.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_63.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_64(Variable vo2_240, AddExpr target_64) {
		target_64.getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_64.getAnOperand().(Literal).getValue()="10"
}

predicate func_65(Variable vo2_240, PointerArithmeticOperation target_92, AddExpr target_65) {
		target_65.getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_65.getAnOperand().(Literal).getValue()="10"
		and target_65.getAnOperand().(VariableAccess).getLocation().isBefore(target_92.getAnOperand().(VariableAccess).getLocation())
}

predicate func_66(Variable vo2_240, RelationalOperation target_66) {
		 (target_66 instanceof GTExpr or target_66 instanceof LTExpr)
		and target_66.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_66.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_66.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_67(Variable vo2_240, RelationalOperation target_67) {
		 (target_67 instanceof GTExpr or target_67 instanceof LTExpr)
		and target_67.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_67.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_67.getGreaterOperand() instanceof Literal
}

predicate func_68(Variable vo2_240, ArrayExpr target_80, AddExpr target_68) {
		target_68.getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_68.getAnOperand().(Literal).getValue()="4"
		and target_68.getAnOperand().(VariableAccess).getLocation().isBefore(target_80.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_69(Variable vo2_240, RelationalOperation target_69) {
		 (target_69 instanceof GTExpr or target_69 instanceof LTExpr)
		and target_69.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_69.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_69.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_70(Variable vo2_240, RelationalOperation target_70) {
		 (target_70 instanceof GTExpr or target_70 instanceof LTExpr)
		and target_70.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_70.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_70.getGreaterOperand() instanceof Literal
}

predicate func_71(Variable vo2_240, ArrayExpr target_82, AddExpr target_71) {
		target_71.getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_71.getAnOperand().(Literal).getValue()="12"
		and target_71.getAnOperand().(VariableAccess).getLocation().isBefore(target_82.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_72(Variable vo2_240, RelationalOperation target_72) {
		 (target_72 instanceof GTExpr or target_72 instanceof LTExpr)
		and target_72.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_72.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_72.getGreaterOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_73(Variable vo2_240, RelationalOperation target_73) {
		 (target_73 instanceof GTExpr or target_73 instanceof LTExpr)
		and target_73.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_73.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_73.getGreaterOperand() instanceof Literal
}

predicate func_74(Variable vo2_240, PointerArithmeticOperation target_110, AddExpr target_74) {
		target_74.getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_74.getAnOperand().(Literal).getValue()="2"
		and target_74.getAnOperand().(VariableAccess).getLocation().isBefore(target_110.getAnOperand().(VariableAccess).getLocation())
}

predicate func_75(Variable vo_240, RelationalOperation target_75) {
		 (target_75 instanceof GTExpr or target_75 instanceof LTExpr)
		and target_75.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_240
		and target_75.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_75.getGreaterOperand().(VariableAccess).getTarget()=vo_240
}

predicate func_76(Variable vo_240, RelationalOperation target_76) {
		 (target_76 instanceof GTExpr or target_76 instanceof LTExpr)
		and target_76.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_240
		and target_76.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_76.getGreaterOperand() instanceof Literal
}

predicate func_77(Variable vo_240, PointerArithmeticOperation target_111, AddExpr target_77) {
		target_77.getAnOperand().(VariableAccess).getTarget()=vo_240
		and target_77.getAnOperand().(Literal).getValue()="12"
		and target_77.getAnOperand().(VariableAccess).getLocation().isBefore(target_111.getAnOperand().(VariableAccess).getLocation())
}

predicate func_78(Variable vs_425, Variable vdataofs_455, RelationalOperation target_78) {
		 (target_78 instanceof GTExpr or target_78 instanceof LTExpr)
		and target_78.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_78.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_425
		and target_78.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_455
}

predicate func_79(Variable vs_425, Variable vdataofs_455, RelationalOperation target_79) {
		 (target_79 instanceof GTExpr or target_79 instanceof LTExpr)
		and target_79.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_79.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_425
		and target_79.getGreaterOperand().(VariableAccess).getTarget()=vs_425
}

predicate func_80(Parameter vbuf_236, Variable vo2_240, ArrayExpr target_80) {
		target_80.getArrayBase().(VariableAccess).getTarget()=vbuf_236
		and target_80.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_80.getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="0"
}

predicate func_81(Variable vo2_240, ExprStmt target_81) {
		target_81.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo2_240
		and target_81.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="6"
}

predicate func_82(Parameter vbuf_236, Variable vo2_240, ArrayExpr target_82) {
		target_82.getArrayBase().(VariableAccess).getTarget()=vbuf_236
		and target_82.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_82.getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="0"
}

predicate func_83(Parameter vbuf_size_236, Variable vo2_240, SubExpr target_83) {
		target_83.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_83.getRightOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_85(Parameter vbuf_size_236, LogicalOrExpr target_85) {
		target_85.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_85.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_85.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_85.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_87(Parameter vbuf_size_236, LogicalOrExpr target_87) {
		target_87.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_87.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_87.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_87.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_88(Variable vn_238, Variable vo2_240, ExprStmt target_88) {
		target_88.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vo2_240
		and target_88.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_88.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_88.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
}

predicate func_89(Parameter vbuf_size_236, LogicalOrExpr target_89) {
		target_89.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_89.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_89.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_89.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_90(Parameter vbuf_size_236, LogicalOrExpr target_90) {
		target_90.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_90.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_90.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_90.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_92(Parameter vbuf_236, Variable vo2_240, PointerArithmeticOperation target_92) {
		target_92.getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_92.getAnOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_93(Parameter ven_235, BlockStmt target_93) {
		target_93.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_93.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_93.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_93.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_93.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_94(Variable vo2_240, ExprStmt target_94) {
		target_94.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo2_240
		and target_94.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
}

predicate func_96(Parameter ven_235, BlockStmt target_96) {
		target_96.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_96.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_96.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_96.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_96.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_97(Parameter vbuf_size_236, LogicalOrExpr target_97) {
		target_97.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_97.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_97.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_97.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_98(Variable vo_240, CommaExpr target_98) {
		target_98.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo_240
		and target_98.getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="12"
}

predicate func_99(Parameter ven_235, Parameter vbuf_size_236, Variable vs_425, Variable vdataofs_455, BlockStmt target_99) {
		target_99.getStmt(1) instanceof IfStmt
		and target_99.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_99.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_99.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_99.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_425
		and target_99.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_100(Parameter vbuf_236, Parameter vbuf_size_236, Variable vn_238, LogicalOrExpr target_100) {
		target_100.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vn_238
		and target_100.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_236
		and target_100.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_101(Parameter vbuf_size_236, LogicalOrExpr target_101) {
		target_101.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_101.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_101.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_101.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_101.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_102(Variable vn_238, Variable vtcount_240, ArrayExpr target_102) {
		target_102.getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_102.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_102.getArrayOffset().(VariableAccess).getTarget()=vtcount_240
}

predicate func_103(Parameter vbuf_236, Parameter vbuf_size_236, Variable vn_238, Variable vo2_240, ExprStmt target_103) {
		target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="version"
		and target_103.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_103.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_mnote_data_olympus_identify_variant")
		and target_103.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_103.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vo2_240
		and target_103.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_236
		and target_103.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_104(Parameter ven_235, Variable vn_238, Variable vtcount_240, ExprStmt target_104) {
		target_104.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_104.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_104.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_104.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_104.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Loading entry 0x%x ('%s')..."
		and target_104.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="tag"
		and target_104.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_104.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_104.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_240
		and target_104.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getTarget().hasName("mnote_olympus_tag_get_name")
		and target_104.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="tag"
		and target_104.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_104.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_104.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_240
}

predicate func_105(Parameter ven_235, Parameter vbuf_size_236, Variable vs_425, Variable vdataofs_455, ExprStmt target_105) {
		target_105.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_105.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_105.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_105.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_105.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_105.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_105.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_425
		and target_105.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_106(Parameter vbuf_236, Variable vn_238, Variable vdatao_240, Variable vdataofs_455, ExprStmt target_106) {
		target_106.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_455
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_238
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_240
}

predicate func_107(Parameter ven_235, Parameter vbuf_size_236, Variable vs_425, Variable vdataofs_455, BlockStmt target_107) {
		target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_235
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteOlympus"
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_455
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_425
		and target_107.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_236
}

predicate func_108(Variable vs_425, RelationalOperation target_108) {
		 (target_108 instanceof GTExpr or target_108 instanceof LTExpr)
		and target_108.getGreaterOperand().(VariableAccess).getTarget()=vs_425
		and target_108.getLesserOperand().(Literal).getValue()="4"
}

predicate func_109(Parameter vbuf_236, Variable vdataofs_455, PointerArithmeticOperation target_109) {
		target_109.getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_109.getAnOperand().(VariableAccess).getTarget()=vdataofs_455
}

predicate func_110(Parameter vbuf_236, Variable vo2_240, PointerArithmeticOperation target_110) {
		target_110.getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_110.getAnOperand().(VariableAccess).getTarget()=vo2_240
}

predicate func_111(Parameter vbuf_236, Variable vo_240, PointerArithmeticOperation target_111) {
		target_111.getAnOperand().(VariableAccess).getTarget()=vbuf_236
		and target_111.getAnOperand().(VariableAccess).getTarget()=vo_240
}

from Function func, Parameter ven_235, Parameter vbuf_236, Parameter vbuf_size_236, Variable vn_238, Variable vtcount_240, Variable vo_240, Variable vo2_240, Variable vdatao_240, Variable vs_425, Variable vdataofs_455, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, DeclStmt target_26, IfStmt target_27, AddExpr target_28, ExprStmt target_29, IfStmt target_30, ExprStmt target_31, VariableAccess target_33, VariableAccess target_35, VariableAccess target_37, VariableAccess target_39, VariableAccess target_41, VariableAccess target_44, VariableAccess target_46, VariableAccess target_48, VariableAccess target_49, VariableAccess target_51, VariableAccess target_52, VariableAccess target_53, VariableAccess target_54, VariableAccess target_55, VariableAccess target_56, VariableAccess target_57, VariableAccess target_58, VariableAccess target_59, VariableAccess target_60, VariableAccess target_61, VariableAccess target_62, RelationalOperation target_63, AddExpr target_64, AddExpr target_65, RelationalOperation target_66, RelationalOperation target_67, AddExpr target_68, RelationalOperation target_69, RelationalOperation target_70, AddExpr target_71, RelationalOperation target_72, RelationalOperation target_73, AddExpr target_74, RelationalOperation target_75, RelationalOperation target_76, AddExpr target_77, RelationalOperation target_78, RelationalOperation target_79, ArrayExpr target_80, ExprStmt target_81, ArrayExpr target_82, SubExpr target_83, LogicalOrExpr target_85, LogicalOrExpr target_87, ExprStmt target_88, LogicalOrExpr target_89, LogicalOrExpr target_90, PointerArithmeticOperation target_92, BlockStmt target_93, ExprStmt target_94, BlockStmt target_96, LogicalOrExpr target_97, CommaExpr target_98, BlockStmt target_99, LogicalOrExpr target_100, LogicalOrExpr target_101, ArrayExpr target_102, ExprStmt target_103, ExprStmt target_104, ExprStmt target_105, ExprStmt target_106, BlockStmt target_107, RelationalOperation target_108, PointerArithmeticOperation target_109, PointerArithmeticOperation target_110, PointerArithmeticOperation target_111
where
func_0(vo2_240, target_0)
and func_1(vo2_240, target_80, target_1)
and func_2(vo2_240, target_81, target_2)
and func_3(vo2_240, target_3)
and func_4(vo2_240, target_82, target_4)
and not func_5(vbuf_size_236, vo2_240, target_83)
and not func_6(vbuf_size_236, target_83, target_85)
and not func_7(vbuf_size_236, vo2_240, target_85)
and not func_8(vbuf_size_236, target_87)
and not func_9(vbuf_size_236, vo2_240, target_88)
and not func_10(vbuf_size_236, target_89)
and not func_11(vbuf_size_236, vo2_240, target_90, target_92)
and not func_12(vbuf_size_236)
and not func_13(vbuf_size_236, vo2_240, target_93, target_94)
and not func_14(vbuf_size_236, vo_240, target_87)
and not func_15(vbuf_size_236)
and not func_16(vbuf_size_236, vo_240, target_96, target_97, target_98)
and not func_17(vbuf_size_236, vn_238, target_99, target_100, target_101, target_102, target_103)
and not func_20(ven_235, vn_238, target_52, target_104, target_105, target_106)
and not func_21(target_52, func)
and not func_22(ven_235, vbuf_size_236, vs_425, vdataofs_455, target_89, target_29, target_97)
and func_26(target_52, func, target_26)
and func_27(vdatao_240, vs_425, vdataofs_455, target_52, target_27)
and func_28(vs_425, vdataofs_455, target_28)
and func_29(ven_235, vn_238, vtcount_240, vs_425, target_52, target_29)
and func_30(ven_235, vn_238, vtcount_240, vs_425, target_52, target_30)
and func_31(vbuf_236, vn_238, vtcount_240, vs_425, vdataofs_455, target_52, target_31)
and func_33(vo2_240, target_33)
and func_35(vbuf_size_236, target_35)
and func_37(vo2_240, target_37)
and func_39(vbuf_size_236, target_39)
and func_41(vo2_240, target_41)
and func_44(vbuf_size_236, target_44)
and func_46(vo2_240, target_46)
and func_48(vbuf_size_236, target_48)
and func_49(vo_240, target_49)
and func_51(vbuf_size_236, target_51)
and func_52(vs_425, target_99, target_52)
and func_53(vs_425, target_53)
and func_54(vdataofs_455, target_54)
and func_55(vs_425, target_55)
and func_56(vbuf_size_236, target_56)
and func_57(vo2_240, target_57)
and func_58(vo2_240, target_58)
and func_59(vo2_240, target_59)
and func_60(vo2_240, target_60)
and func_61(vo_240, target_61)
and func_62(vdataofs_455, target_62)
and func_63(vo2_240, target_63)
and func_64(vo2_240, target_64)
and func_65(vo2_240, target_92, target_65)
and func_66(vo2_240, target_66)
and func_67(vo2_240, target_67)
and func_68(vo2_240, target_80, target_68)
and func_69(vo2_240, target_69)
and func_70(vo2_240, target_70)
and func_71(vo2_240, target_82, target_71)
and func_72(vo2_240, target_72)
and func_73(vo2_240, target_73)
and func_74(vo2_240, target_110, target_74)
and func_75(vo_240, target_75)
and func_76(vo_240, target_76)
and func_77(vo_240, target_111, target_77)
and func_78(vs_425, vdataofs_455, target_78)
and func_79(vs_425, vdataofs_455, target_79)
and func_80(vbuf_236, vo2_240, target_80)
and func_81(vo2_240, target_81)
and func_82(vbuf_236, vo2_240, target_82)
and func_83(vbuf_size_236, vo2_240, target_83)
and func_85(vbuf_size_236, target_85)
and func_87(vbuf_size_236, target_87)
and func_88(vn_238, vo2_240, target_88)
and func_89(vbuf_size_236, target_89)
and func_90(vbuf_size_236, target_90)
and func_92(vbuf_236, vo2_240, target_92)
and func_93(ven_235, target_93)
and func_94(vo2_240, target_94)
and func_96(ven_235, target_96)
and func_97(vbuf_size_236, target_97)
and func_98(vo_240, target_98)
and func_99(ven_235, vbuf_size_236, vs_425, vdataofs_455, target_99)
and func_100(vbuf_236, vbuf_size_236, vn_238, target_100)
and func_101(vbuf_size_236, target_101)
and func_102(vn_238, vtcount_240, target_102)
and func_103(vbuf_236, vbuf_size_236, vn_238, vo2_240, target_103)
and func_104(ven_235, vn_238, vtcount_240, target_104)
and func_105(ven_235, vbuf_size_236, vs_425, vdataofs_455, target_105)
and func_106(vbuf_236, vn_238, vdatao_240, vdataofs_455, target_106)
and func_107(ven_235, vbuf_size_236, vs_425, vdataofs_455, target_107)
and func_108(vs_425, target_108)
and func_109(vbuf_236, vdataofs_455, target_109)
and func_110(vbuf_236, vo2_240, target_110)
and func_111(vbuf_236, vo_240, target_111)
and ven_235.getType().hasName("ExifMnoteData *")
and vbuf_236.getType().hasName("const unsigned char *")
and vbuf_size_236.getType().hasName("unsigned int")
and vn_238.getType().hasName("ExifMnoteDataOlympus *")
and vtcount_240.getType().hasName("size_t")
and vo_240.getType().hasName("size_t")
and vo2_240.getType().hasName("size_t")
and vdatao_240.getType().hasName("size_t")
and vs_425.getType().hasName("size_t")
and vdataofs_455.getType().hasName("size_t")
and ven_235.getParentScope+() = func
and vbuf_236.getParentScope+() = func
and vbuf_size_236.getParentScope+() = func
and vn_238.getParentScope+() = func
and vtcount_240.getParentScope+() = func
and vo_240.getParentScope+() = func
and vo2_240.getParentScope+() = func
and vdatao_240.getParentScope+() = func
and vs_425.getParentScope+() = func
and vdataofs_455.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
