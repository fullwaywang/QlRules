/**
 * @name libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-exif_mnote_data_fuji_load
 * @id cpp/libexif/435e21f05001fb03f9f186fa7cbc69454afd00d1/exif-mnote-data-fuji-load
 * @description libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-libexif/fuji/exif-mnote-data-fuji.c-exif_mnote_data_fuji_load CVE-2020-13112
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdatao_157, ExprStmt target_58, VariableAccess target_0) {
		target_0.getTarget()=vdatao_157
		and target_0.getLocation().isBefore(target_58.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_1(Variable vdatao_157, PointerArithmeticOperation target_59, VariableAccess target_1) {
		target_1.getTarget()=vdatao_157
		and target_59.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vdatao_157, VariableAccess target_2) {
		target_2.getTarget()=vdatao_157
}

predicate func_3(Variable vdatao_157, PointerArithmeticOperation target_62, VariableAccess target_3) {
		target_3.getTarget()=vdatao_157
		and target_3.getLocation().isBefore(target_62.getAnOperand().(VariableAccess).getLocation())
}

predicate func_4(Variable vo_157, VariableAccess target_4) {
		target_4.getTarget()=vo_157
}

predicate func_5(Parameter vbuf_size_153, LogicalOrExpr target_63) {
	exists(SubExpr target_5 |
		target_5.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_5.getRightOperand() instanceof Literal
		and target_5.getLeftOperand().(VariableAccess).getLocation().isBefore(target_63.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vbuf_size_153, Variable vdatao_157, ExprStmt target_64) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vdatao_157
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vbuf_size_153, Variable vdatao_157, BlockStmt target_65, LogicalOrExpr target_66) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vdatao_157
		and target_7.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_7.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_7.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_65
		and target_66.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vbuf_size_153, Variable vo_157, LogicalOrExpr target_63) {
	exists(RelationalOperation target_8 |
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vo_157
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_63.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vbuf_size_153) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand() instanceof Literal
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153)
}

predicate func_10(Parameter vbuf_size_153, Variable vo_157, BlockStmt target_68, LogicalOrExpr target_69, CommaExpr target_70) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vo_157
		and target_10.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_10.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_68
		and target_10.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_69.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_70.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vbuf_size_153, Variable vn_155, BlockStmt target_71, LogicalOrExpr target_72, LogicalOrExpr target_66, ArrayExpr target_73, ExprStmt target_74) {
	exists(LogicalAndExpr target_11 |
		target_11.getAnOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="components"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_11.getParent().(IfStmt).getThen()=target_71
		and target_72.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_66.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_73.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_74.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_12(Parameter vbuf_size_153, Variable vn_155, LogicalOrExpr target_72, LogicalOrExpr target_66, ExprStmt target_64) {
	exists(DivExpr target_12 |
		target_12.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_12.getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_12.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_12.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_12.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_12.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_72.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getLeftOperand().(VariableAccess).getLocation())
		and target_12.getLeftOperand().(VariableAccess).getLocation().isBefore(target_66.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_13(Variable vn_155, ExprStmt target_74) {
	exists(ValueFieldAccess target_13 |
		target_13.getTarget().getName()="components"
		and target_13.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_13.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_13.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_13.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_74.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_14(Parameter ven_152, Variable vn_155, VariableAccess target_38, ExprStmt target_75, ExprStmt target_76, ExprStmt target_77) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_14.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_14.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag size overflow detected (%u * %lu)"
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_14.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="components"
		and target_14.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_14.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_14.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_75.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_76.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(VariableAccess target_38, Function func) {
	exists(ContinueStmt target_15 |
		target_15.toString() = "continue;"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter ven_152, Parameter vbuf_size_153, Variable vs_197, Variable vdataofs_220, LogicalOrExpr target_78, ExprStmt target_23, LogicalOrExpr target_69) {
	exists(IfStmt target_16 |
		target_16.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_197
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_16.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_197
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u >= %u)"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_153
		and target_16.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_16
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_78
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_69.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_16.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_17(Parameter vbuf_size_153, Variable vdataofs_220, LogicalOrExpr target_69, LogicalOrExpr target_78) {
	exists(RelationalOperation target_17 |
		 (target_17 instanceof GEExpr or target_17 instanceof LEExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_69.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_17.getLesserOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_18(Parameter vbuf_size_153, Variable vs_197, LogicalOrExpr target_78) {
	exists(RelationalOperation target_18 |
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(VariableAccess).getTarget()=vs_197
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153)
}

*/
/*predicate func_19(Parameter vbuf_size_153, Variable vs_197, Variable vdataofs_220, BlockStmt target_79, LogicalOrExpr target_78, RelationalOperation target_80, PointerArithmeticOperation target_81) {
	exists(RelationalOperation target_19 |
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_19.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_19.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_197
		and target_19.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_19.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_19.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_19.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_19.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_79
		and target_19.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_78.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_80.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_19.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_81.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_20(VariableAccess target_38, Function func, DeclStmt target_20) {
		target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Variable vn_155, Variable vs_197, Variable vdataofs_220, VariableAccess target_38, IfStmt target_21) {
		target_21.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_197
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_220
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
}

predicate func_22(Variable vs_197, Variable vdataofs_220, AddExpr target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_22.getAnOperand().(VariableAccess).getTarget()=vs_197
}

predicate func_23(Parameter ven_152, Variable vn_155, Variable vtcount_157, Variable vs_197, VariableAccess target_38, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_157
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_mem_alloc")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_197
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
}

predicate func_24(Parameter ven_152, Variable vn_155, Variable vtcount_157, Variable vs_197, VariableAccess target_38, IfStmt target_24) {
		target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_157
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Could not allocate %lu byte(s)."
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_197
		and target_24.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
}

predicate func_25(Parameter vbuf_153, Variable vn_155, Variable vtcount_157, Variable vs_197, Variable vdataofs_220, VariableAccess target_38, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_157
		and target_25.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_25.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_25.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_197
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
}

predicate func_27(Variable vdatao_157, VariableAccess target_27) {
		target_27.getTarget()=vdatao_157
}

predicate func_30(Parameter vbuf_size_153, VariableAccess target_30) {
		target_30.getTarget()=vbuf_size_153
}

predicate func_32(Variable vdatao_157, VariableAccess target_32) {
		target_32.getTarget()=vdatao_157
}

predicate func_34(Parameter vbuf_size_153, VariableAccess target_34) {
		target_34.getTarget()=vbuf_size_153
}

predicate func_35(Variable vo_157, VariableAccess target_35) {
		target_35.getTarget()=vo_157
}

predicate func_37(Parameter vbuf_size_153, VariableAccess target_37) {
		target_37.getTarget()=vbuf_size_153
}

predicate func_38(Variable vs_197, BlockStmt target_71, VariableAccess target_38) {
		target_38.getTarget()=vs_197
		and target_38.getParent().(IfStmt).getThen()=target_71
}

predicate func_39(Variable vs_197, VariableAccess target_39) {
		target_39.getTarget()=vs_197
}

predicate func_40(Variable vdataofs_220, VariableAccess target_40) {
		target_40.getTarget()=vdataofs_220
}

predicate func_41(Variable vs_197, VariableAccess target_41) {
		target_41.getTarget()=vs_197
}

predicate func_42(Parameter vbuf_size_153, VariableAccess target_42) {
		target_42.getTarget()=vbuf_size_153
}

predicate func_43(Variable vdatao_157, VariableAccess target_43) {
		target_43.getTarget()=vdatao_157
}

predicate func_44(Variable vdatao_157, VariableAccess target_44) {
		target_44.getTarget()=vdatao_157
}

predicate func_45(Variable vo_157, VariableAccess target_45) {
		target_45.getTarget()=vo_157
}

predicate func_46(Variable vdataofs_220, VariableAccess target_46) {
		target_46.getTarget()=vdataofs_220
}

predicate func_47(Variable vdatao_157, RelationalOperation target_47) {
		 (target_47 instanceof GTExpr or target_47 instanceof LTExpr)
		and target_47.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_47.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_47.getGreaterOperand().(VariableAccess).getTarget()=vdatao_157
}

predicate func_48(Variable vdatao_157, AddExpr target_48) {
		target_48.getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_48.getAnOperand() instanceof Literal
}

predicate func_49(Variable vdatao_157, ExprStmt target_58, AddExpr target_49) {
		target_49.getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_49.getAnOperand().(Literal).getValue()="12"
		and target_49.getAnOperand().(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_50(Variable vdatao_157, RelationalOperation target_50) {
		 (target_50 instanceof GTExpr or target_50 instanceof LTExpr)
		and target_50.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_50.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_50.getGreaterOperand().(VariableAccess).getTarget()=vdatao_157
}

predicate func_51(Variable vdatao_157, RelationalOperation target_51) {
		 (target_51 instanceof GTExpr or target_51 instanceof LTExpr)
		and target_51.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_51.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_51.getGreaterOperand() instanceof Literal
}

predicate func_52(Variable vdatao_157, LogicalOrExpr target_63, PointerArithmeticOperation target_62, AddExpr target_52) {
		target_52.getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_52.getAnOperand().(Literal).getValue()="2"
		and target_52.getAnOperand().(VariableAccess).getLocation().isBefore(target_62.getAnOperand().(VariableAccess).getLocation())
}

predicate func_53(Variable vo_157, RelationalOperation target_53) {
		 (target_53 instanceof GTExpr or target_53 instanceof LTExpr)
		and target_53.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_157
		and target_53.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_53.getGreaterOperand().(VariableAccess).getTarget()=vo_157
}

predicate func_54(Variable vo_157, RelationalOperation target_54) {
		 (target_54 instanceof GTExpr or target_54 instanceof LTExpr)
		and target_54.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_157
		and target_54.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_54.getGreaterOperand() instanceof Literal
}

predicate func_55(Variable vo_157, PointerArithmeticOperation target_82, AddExpr target_55) {
		target_55.getAnOperand().(VariableAccess).getTarget()=vo_157
		and target_55.getAnOperand().(Literal).getValue()="12"
		and target_55.getAnOperand().(VariableAccess).getLocation().isBefore(target_82.getAnOperand().(VariableAccess).getLocation())
}

predicate func_56(Variable vs_197, Variable vdataofs_220, RelationalOperation target_56) {
		 (target_56 instanceof GTExpr or target_56 instanceof LTExpr)
		and target_56.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_56.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_197
		and target_56.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_220
}

predicate func_57(Variable vs_197, Variable vdataofs_220, RelationalOperation target_57) {
		 (target_57 instanceof GTExpr or target_57 instanceof LTExpr)
		and target_57.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_57.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_197
		and target_57.getGreaterOperand().(VariableAccess).getTarget()=vs_197
}

predicate func_58(Parameter vbuf_153, Variable vdatao_157, ExprStmt target_58) {
		target_58.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vdatao_157
		and target_58.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_58.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_58.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_58.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="8"
}

predicate func_59(Parameter vbuf_153, Variable vdatao_157, PointerArithmeticOperation target_59) {
		target_59.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_59.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdatao_157
		and target_59.getAnOperand().(Literal).getValue()="8"
}

predicate func_62(Parameter vbuf_153, Variable vdatao_157, PointerArithmeticOperation target_62) {
		target_62.getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_62.getAnOperand().(VariableAccess).getTarget()=vdatao_157
}

predicate func_63(Parameter vbuf_size_153, LogicalOrExpr target_63) {
		target_63.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_63.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_63.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_63.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_64(Variable vn_155, Variable vdatao_157, ExprStmt target_64) {
		target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdatao_157
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
}

predicate func_65(Parameter ven_152, BlockStmt target_65) {
		target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_66(Parameter vbuf_size_153, LogicalOrExpr target_66) {
		target_66.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_66.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_66.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_66.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_66.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_68(Parameter ven_152, BlockStmt target_68) {
		target_68.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_68.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_68.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_68.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_68.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_69(Parameter vbuf_size_153, LogicalOrExpr target_69) {
		target_69.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_69.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_69.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_69.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_70(Variable vo_157, CommaExpr target_70) {
		target_70.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo_157
		and target_70.getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="12"
}

predicate func_71(Parameter ven_152, Parameter vbuf_size_153, Variable vs_197, Variable vdataofs_220, BlockStmt target_71) {
		target_71.getStmt(1) instanceof IfStmt
		and target_71.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_71.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_71.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_71.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u >= %u)"
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_197
		and target_71.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_72(Parameter vbuf_153, Parameter vbuf_size_153, Variable vn_155, LogicalOrExpr target_72) {
		target_72.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vn_155
		and target_72.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_153
		and target_72.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_73(Variable vn_155, Variable vtcount_157, ArrayExpr target_73) {
		target_73.getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_73.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_73.getArrayOffset().(VariableAccess).getTarget()=vtcount_157
}

predicate func_74(Variable vn_155, ExprStmt target_74) {
		target_74.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="order"
		and target_74.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
}

predicate func_75(Parameter ven_152, Variable vn_155, Variable vtcount_157, ExprStmt target_75) {
		target_75.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_75.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_75.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_75.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_75.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Loading entry 0x%x ('%s')..."
		and target_75.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="tag"
		and target_75.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_75.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_75.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_157
		and target_75.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getTarget().hasName("mnote_fuji_tag_get_name")
		and target_75.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="tag"
		and target_75.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_75.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_75.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_157
}

predicate func_76(Parameter ven_152, Parameter vbuf_size_153, Variable vs_197, Variable vdataofs_220, ExprStmt target_76) {
		target_76.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_76.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_76.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_76.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_76.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u >= %u)"
		and target_76.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_76.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_197
		and target_76.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_77(Parameter vbuf_153, Variable vn_155, Variable vdataofs_220, ExprStmt target_77) {
		target_77.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_220
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_77.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_155
}

predicate func_78(Parameter vbuf_size_153, LogicalOrExpr target_78) {
		target_78.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_78.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_78.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_78.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_79(Parameter ven_152, Parameter vbuf_size_153, Variable vs_197, Variable vdataofs_220, BlockStmt target_79) {
		target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_152
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataFuji"
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u >= %u)"
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_220
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_197
		and target_79.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_153
}

predicate func_80(Variable vs_197, RelationalOperation target_80) {
		 (target_80 instanceof GTExpr or target_80 instanceof LTExpr)
		and target_80.getGreaterOperand().(VariableAccess).getTarget()=vs_197
		and target_80.getLesserOperand().(Literal).getValue()="4"
}

predicate func_81(Parameter vbuf_153, Variable vdataofs_220, PointerArithmeticOperation target_81) {
		target_81.getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_81.getAnOperand().(VariableAccess).getTarget()=vdataofs_220
}

predicate func_82(Parameter vbuf_153, Variable vo_157, PointerArithmeticOperation target_82) {
		target_82.getAnOperand().(VariableAccess).getTarget()=vbuf_153
		and target_82.getAnOperand().(VariableAccess).getTarget()=vo_157
}

from Function func, Parameter ven_152, Parameter vbuf_153, Parameter vbuf_size_153, Variable vn_155, Variable vtcount_157, Variable vo_157, Variable vdatao_157, Variable vs_197, Variable vdataofs_220, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, DeclStmt target_20, IfStmt target_21, AddExpr target_22, ExprStmt target_23, IfStmt target_24, ExprStmt target_25, VariableAccess target_27, VariableAccess target_30, VariableAccess target_32, VariableAccess target_34, VariableAccess target_35, VariableAccess target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, VariableAccess target_41, VariableAccess target_42, VariableAccess target_43, VariableAccess target_44, VariableAccess target_45, VariableAccess target_46, RelationalOperation target_47, AddExpr target_48, AddExpr target_49, RelationalOperation target_50, RelationalOperation target_51, AddExpr target_52, RelationalOperation target_53, RelationalOperation target_54, AddExpr target_55, RelationalOperation target_56, RelationalOperation target_57, ExprStmt target_58, PointerArithmeticOperation target_59, PointerArithmeticOperation target_62, LogicalOrExpr target_63, ExprStmt target_64, BlockStmt target_65, LogicalOrExpr target_66, BlockStmt target_68, LogicalOrExpr target_69, CommaExpr target_70, BlockStmt target_71, LogicalOrExpr target_72, ArrayExpr target_73, ExprStmt target_74, ExprStmt target_75, ExprStmt target_76, ExprStmt target_77, LogicalOrExpr target_78, BlockStmt target_79, RelationalOperation target_80, PointerArithmeticOperation target_81, PointerArithmeticOperation target_82
where
func_0(vdatao_157, target_58, target_0)
and func_1(vdatao_157, target_59, target_1)
and func_2(vdatao_157, target_2)
and func_3(vdatao_157, target_62, target_3)
and func_4(vo_157, target_4)
and not func_5(vbuf_size_153, target_63)
and not func_6(vbuf_size_153, vdatao_157, target_64)
and not func_7(vbuf_size_153, vdatao_157, target_65, target_66)
and not func_8(vbuf_size_153, vo_157, target_63)
and not func_9(vbuf_size_153)
and not func_10(vbuf_size_153, vo_157, target_68, target_69, target_70)
and not func_11(vbuf_size_153, vn_155, target_71, target_72, target_66, target_73, target_74)
and not func_14(ven_152, vn_155, target_38, target_75, target_76, target_77)
and not func_15(target_38, func)
and not func_16(ven_152, vbuf_size_153, vs_197, vdataofs_220, target_78, target_23, target_69)
and func_20(target_38, func, target_20)
and func_21(vn_155, vs_197, vdataofs_220, target_38, target_21)
and func_22(vs_197, vdataofs_220, target_22)
and func_23(ven_152, vn_155, vtcount_157, vs_197, target_38, target_23)
and func_24(ven_152, vn_155, vtcount_157, vs_197, target_38, target_24)
and func_25(vbuf_153, vn_155, vtcount_157, vs_197, vdataofs_220, target_38, target_25)
and func_27(vdatao_157, target_27)
and func_30(vbuf_size_153, target_30)
and func_32(vdatao_157, target_32)
and func_34(vbuf_size_153, target_34)
and func_35(vo_157, target_35)
and func_37(vbuf_size_153, target_37)
and func_38(vs_197, target_71, target_38)
and func_39(vs_197, target_39)
and func_40(vdataofs_220, target_40)
and func_41(vs_197, target_41)
and func_42(vbuf_size_153, target_42)
and func_43(vdatao_157, target_43)
and func_44(vdatao_157, target_44)
and func_45(vo_157, target_45)
and func_46(vdataofs_220, target_46)
and func_47(vdatao_157, target_47)
and func_48(vdatao_157, target_48)
and func_49(vdatao_157, target_58, target_49)
and func_50(vdatao_157, target_50)
and func_51(vdatao_157, target_51)
and func_52(vdatao_157, target_63, target_62, target_52)
and func_53(vo_157, target_53)
and func_54(vo_157, target_54)
and func_55(vo_157, target_82, target_55)
and func_56(vs_197, vdataofs_220, target_56)
and func_57(vs_197, vdataofs_220, target_57)
and func_58(vbuf_153, vdatao_157, target_58)
and func_59(vbuf_153, vdatao_157, target_59)
and func_62(vbuf_153, vdatao_157, target_62)
and func_63(vbuf_size_153, target_63)
and func_64(vn_155, vdatao_157, target_64)
and func_65(ven_152, target_65)
and func_66(vbuf_size_153, target_66)
and func_68(ven_152, target_68)
and func_69(vbuf_size_153, target_69)
and func_70(vo_157, target_70)
and func_71(ven_152, vbuf_size_153, vs_197, vdataofs_220, target_71)
and func_72(vbuf_153, vbuf_size_153, vn_155, target_72)
and func_73(vn_155, vtcount_157, target_73)
and func_74(vn_155, target_74)
and func_75(ven_152, vn_155, vtcount_157, target_75)
and func_76(ven_152, vbuf_size_153, vs_197, vdataofs_220, target_76)
and func_77(vbuf_153, vn_155, vdataofs_220, target_77)
and func_78(vbuf_size_153, target_78)
and func_79(ven_152, vbuf_size_153, vs_197, vdataofs_220, target_79)
and func_80(vs_197, target_80)
and func_81(vbuf_153, vdataofs_220, target_81)
and func_82(vbuf_153, vo_157, target_82)
and ven_152.getType().hasName("ExifMnoteData *")
and vbuf_153.getType().hasName("const unsigned char *")
and vbuf_size_153.getType().hasName("unsigned int")
and vn_155.getType().hasName("ExifMnoteDataFuji *")
and vtcount_157.getType().hasName("size_t")
and vo_157.getType().hasName("size_t")
and vdatao_157.getType().hasName("size_t")
and vs_197.getType().hasName("size_t")
and vdataofs_220.getType().hasName("size_t")
and ven_152.getParentScope+() = func
and vbuf_153.getParentScope+() = func
and vbuf_size_153.getParentScope+() = func
and vn_155.getParentScope+() = func
and vtcount_157.getParentScope+() = func
and vo_157.getParentScope+() = func
and vdatao_157.getParentScope+() = func
and vs_197.getParentScope+() = func
and vdataofs_220.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
