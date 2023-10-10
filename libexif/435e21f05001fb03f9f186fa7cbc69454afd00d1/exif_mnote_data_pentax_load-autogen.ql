/**
 * @name libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-exif_mnote_data_pentax_load
 * @id cpp/libexif/435e21f05001fb03f9f186fa7cbc69454afd00d1/exif-mnote-data-pentax-load
 * @description libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-libexif/pentax/exif-mnote-data-pentax.c-exif_mnote_data_pentax_load CVE-2020-13112
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdatao_218, VariableAccess target_0) {
		target_0.getTarget()=vdatao_218
}

predicate func_1(Variable vdatao_218, PointerArithmeticOperation target_49, VariableAccess target_1) {
		target_1.getTarget()=vdatao_218
		and target_1.getLocation().isBefore(target_49.getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vo_218, VariableAccess target_2) {
		target_2.getTarget()=vo_218
}

predicate func_3(Variable vo_218, PointerArithmeticOperation target_50, VariableAccess target_3) {
		target_3.getTarget()=vo_218
		and target_3.getLocation().isBefore(target_50.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_4(Variable vdataofs_303, VariableAccess target_4) {
		target_4.getTarget()=vdataofs_303
}

predicate func_5(Parameter vbuf_size_215, Variable vdatao_218) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vdatao_218
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215)
}

predicate func_6(Parameter vbuf_size_215, LogicalOrExpr target_53) {
	exists(SubExpr target_6 |
		target_6.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_6.getRightOperand() instanceof Literal
		and target_6.getLeftOperand().(VariableAccess).getLocation().isBefore(target_53.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vbuf_size_215, Variable vo_218, ExprStmt target_54, LogicalOrExpr target_53) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vo_218
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_54.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vbuf_size_215, Variable vo_218, BlockStmt target_55, LogicalOrExpr target_56, CommaExpr target_57) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vo_218
		and target_9.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_9.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_9.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_55
		and target_56.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_57.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vbuf_size_215, Variable vn_217, BlockStmt target_58, LogicalOrExpr target_59, LogicalOrExpr target_56, ArrayExpr target_60, ExprStmt target_61) {
	exists(LogicalAndExpr target_10 |
		target_10.getAnOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="components"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getParent().(IfStmt).getThen()=target_58
		and target_59.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_56.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_60.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_61.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Parameter vbuf_size_215, Variable vn_217, LogicalOrExpr target_59, LogicalOrExpr target_56, ExprStmt target_62) {
	exists(DivExpr target_11 |
		target_11.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_11.getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_59.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(VariableAccess).getLocation())
		and target_11.getLeftOperand().(VariableAccess).getLocation().isBefore(target_56.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_62.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_12(Variable vn_217, ExprStmt target_61) {
	exists(ValueFieldAccess target_12 |
		target_12.getTarget().getName()="components"
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_12.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_61.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Parameter ven_214, Variable vn_217, VariableAccess target_33, ExprStmt target_63, ExprStmt target_54, ExprStmt target_64) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_13.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_13.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag size overflow detected (%u * %lu)"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="components"
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_63.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_54.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_14(VariableAccess target_33, Function func) {
	exists(BreakStmt target_14 |
		target_14.toString() = "break;"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Parameter ven_214, Parameter vbuf_size_215, Variable vs_279, Variable vdataofs_303, LogicalOrExpr target_65, ExprStmt target_22, LogicalOrExpr target_53) {
	exists(IfStmt target_15 |
		target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_279
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_279
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_215
		and target_15.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_65
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_53.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_16(Parameter vbuf_size_215, Variable vdataofs_303, LogicalOrExpr target_53, LogicalOrExpr target_65) {
	exists(RelationalOperation target_16 |
		 (target_16 instanceof GEExpr or target_16 instanceof LEExpr)
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_16.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_53.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_16.getLesserOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_17(Parameter vbuf_size_215, Variable vs_279, LogicalOrExpr target_65) {
	exists(RelationalOperation target_17 |
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vs_279
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215)
}

*/
/*predicate func_18(Parameter vbuf_size_215, Variable vs_279, Variable vdataofs_303, BlockStmt target_66, RelationalOperation target_67, PointerArithmeticOperation target_68) {
	exists(RelationalOperation target_18 |
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_18.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_18.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_279
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_18.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_66
		and target_67.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_68.getAnOperand().(VariableAccess).getLocation().isBefore(target_18.getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_19(VariableAccess target_33, Function func, DeclStmt target_19) {
		target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Parameter vbuf_215, Variable vn_217, Variable vs_279, Variable vdataofs_303, VariableAccess target_33, IfStmt target_20) {
		target_20.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_279
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_303
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_20.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

predicate func_21(Variable vs_279, Variable vdataofs_303, AddExpr target_21) {
		target_21.getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_21.getAnOperand().(VariableAccess).getTarget()=vs_279
}

predicate func_22(Parameter ven_214, Variable vn_217, Variable vtcount_218, Variable vs_279, VariableAccess target_33, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_218
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_mem_alloc")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_279
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

predicate func_23(Parameter ven_214, Variable vn_217, Variable vtcount_218, Variable vs_279, VariableAccess target_33, IfStmt target_23) {
		target_23.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_23.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_23.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_23.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_218
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Could not allocate %lu byte(s)."
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_279
		and target_23.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

predicate func_24(Parameter vbuf_215, Variable vn_217, Variable vtcount_218, Variable vs_279, Variable vdataofs_303, VariableAccess target_33, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_24.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_24.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_24.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_24.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_218
		and target_24.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_24.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_24.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_279
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

predicate func_26(Variable vdatao_218, VariableAccess target_26) {
		target_26.getTarget()=vdatao_218
}

predicate func_28(Parameter vbuf_size_215, VariableAccess target_28) {
		target_28.getTarget()=vbuf_size_215
}

predicate func_30(Variable vo_218, VariableAccess target_30) {
		target_30.getTarget()=vo_218
}

predicate func_32(Parameter vbuf_size_215, VariableAccess target_32) {
		target_32.getTarget()=vbuf_size_215
}

predicate func_33(Variable vs_279, BlockStmt target_58, VariableAccess target_33) {
		target_33.getTarget()=vs_279
		and target_33.getParent().(IfStmt).getThen()=target_58
}

predicate func_34(Variable vs_279, VariableAccess target_34) {
		target_34.getTarget()=vs_279
}

predicate func_35(Variable vdataofs_303, VariableAccess target_35) {
		target_35.getTarget()=vdataofs_303
}

predicate func_36(Variable vs_279, VariableAccess target_36) {
		target_36.getTarget()=vs_279
}

predicate func_37(Parameter vbuf_size_215, VariableAccess target_37) {
		target_37.getTarget()=vbuf_size_215
}

predicate func_38(Variable vdatao_218, VariableAccess target_38) {
		target_38.getTarget()=vdatao_218
}

predicate func_39(Variable vo_218, VariableAccess target_39) {
		target_39.getTarget()=vo_218
}

predicate func_40(Variable vdataofs_303, VariableAccess target_40) {
		target_40.getTarget()=vdataofs_303
}

predicate func_41(Variable vdatao_218, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_218
		and target_41.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_41.getGreaterOperand().(VariableAccess).getTarget()=vdatao_218
}

predicate func_42(Variable vdatao_218, AddExpr target_42) {
		target_42.getAnOperand().(VariableAccess).getTarget()=vdatao_218
		and target_42.getAnOperand().(Literal).getValue()="8"
}

predicate func_43(Variable vdatao_218, PointerArithmeticOperation target_49, AddExpr target_43) {
		target_43.getAnOperand().(VariableAccess).getTarget()=vdatao_218
		and target_43.getAnOperand().(Literal).getValue()="8"
		and target_43.getAnOperand().(VariableAccess).getLocation().isBefore(target_49.getAnOperand().(VariableAccess).getLocation())
}

predicate func_44(Variable vo_218, RelationalOperation target_44) {
		 (target_44 instanceof GTExpr or target_44 instanceof LTExpr)
		and target_44.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_218
		and target_44.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_44.getGreaterOperand().(VariableAccess).getTarget()=vo_218
}

predicate func_45(Variable vo_218, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_218
		and target_45.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_45.getGreaterOperand() instanceof Literal
}

predicate func_46(Variable vo_218, PointerArithmeticOperation target_50, AddExpr target_46) {
		target_46.getAnOperand().(VariableAccess).getTarget()=vo_218
		and target_46.getAnOperand().(Literal).getValue()="12"
		and target_46.getAnOperand().(VariableAccess).getLocation().isBefore(target_50.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_47(Variable vs_279, Variable vdataofs_303, RelationalOperation target_47) {
		 (target_47 instanceof GTExpr or target_47 instanceof LTExpr)
		and target_47.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_47.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_279
		and target_47.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_303
}

predicate func_48(Variable vs_279, Variable vdataofs_303, RelationalOperation target_48) {
		 (target_48 instanceof GTExpr or target_48 instanceof LTExpr)
		and target_48.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_48.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_279
		and target_48.getGreaterOperand().(VariableAccess).getTarget()=vs_279
}

predicate func_49(Parameter vbuf_215, Variable vdatao_218, PointerArithmeticOperation target_49) {
		target_49.getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_49.getAnOperand().(VariableAccess).getTarget()=vdatao_218
}

predicate func_50(Parameter vbuf_215, Variable vo_218, PointerArithmeticOperation target_50) {
		target_50.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_50.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vo_218
		and target_50.getAnOperand().(Literal).getValue()="0"
}

predicate func_53(Parameter vbuf_size_215, LogicalOrExpr target_53) {
		target_53.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_53.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_53.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_53.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_54(Parameter ven_214, Parameter vbuf_size_215, Variable vs_279, Variable vdataofs_303, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_54.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_54.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_54.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_54.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_54.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_54.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_279
		and target_54.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_55(Parameter ven_214, BlockStmt target_55) {
		target_55.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_55.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_55.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_55.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_55.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_56(Parameter vbuf_size_215, LogicalOrExpr target_56) {
		target_56.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_56.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_56.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_56.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_56.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_57(Variable vo_218, CommaExpr target_57) {
		target_57.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo_218
		and target_57.getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="12"
}

predicate func_58(Parameter ven_214, Parameter vbuf_size_215, Variable vs_279, Variable vdataofs_303, BlockStmt target_58) {
		target_58.getStmt(1) instanceof IfStmt
		and target_58.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_58.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_58.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_58.getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_279
		and target_58.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_59(Parameter vbuf_215, Parameter vbuf_size_215, Variable vn_217, LogicalOrExpr target_59) {
		target_59.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vn_217
		and target_59.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_215
		and target_59.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_60(Variable vn_217, Variable vtcount_218, ArrayExpr target_60) {
		target_60.getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_60.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_60.getArrayOffset().(VariableAccess).getTarget()=vtcount_218
}

predicate func_61(Variable vn_217, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="version"
		and target_61.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
}

predicate func_62(Variable vn_217, Variable vdatao_218, ExprStmt target_62) {
		target_62.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdatao_218
		and target_62.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_62.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_62.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
}

predicate func_63(Parameter ven_214, Variable vn_217, Variable vtcount_218, ExprStmt target_63) {
		target_63.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_63.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_63.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_63.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnotePentax"
		and target_63.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Loading entry 0x%x ('%s')..."
		and target_63.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="tag"
		and target_63.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_63.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_63.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_218
		and target_63.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getTarget().hasName("mnote_pentax_tag_get_name")
		and target_63.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="tag"
		and target_63.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_63.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_63.getExpr().(FunctionCall).getArgument(5).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_218
}

predicate func_64(Parameter vbuf_215, Variable vn_217, Variable vdataofs_303, ExprStmt target_64) {
		target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_303
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_217
		and target_64.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
}

predicate func_65(Parameter vbuf_size_215, LogicalOrExpr target_65) {
		target_65.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_65.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_65.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_65.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_66(Parameter ven_214, Parameter vbuf_size_215, Variable vs_279, Variable vdataofs_303, BlockStmt target_66) {
		target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ven_214
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteDataPentax"
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_303
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_279
		and target_66.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_215
}

predicate func_67(Variable vs_279, RelationalOperation target_67) {
		 (target_67 instanceof GTExpr or target_67 instanceof LTExpr)
		and target_67.getGreaterOperand().(VariableAccess).getTarget()=vs_279
		and target_67.getLesserOperand().(Literal).getValue()="4"
}

predicate func_68(Parameter vbuf_215, Variable vdataofs_303, PointerArithmeticOperation target_68) {
		target_68.getAnOperand().(VariableAccess).getTarget()=vbuf_215
		and target_68.getAnOperand().(VariableAccess).getTarget()=vdataofs_303
}

from Function func, Parameter ven_214, Parameter vbuf_215, Parameter vbuf_size_215, Variable vn_217, Variable vtcount_218, Variable vo_218, Variable vdatao_218, Variable vs_279, Variable vdataofs_303, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, DeclStmt target_19, IfStmt target_20, AddExpr target_21, ExprStmt target_22, IfStmt target_23, ExprStmt target_24, VariableAccess target_26, VariableAccess target_28, VariableAccess target_30, VariableAccess target_32, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, VariableAccess target_36, VariableAccess target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, RelationalOperation target_41, AddExpr target_42, AddExpr target_43, RelationalOperation target_44, RelationalOperation target_45, AddExpr target_46, RelationalOperation target_47, RelationalOperation target_48, PointerArithmeticOperation target_49, PointerArithmeticOperation target_50, LogicalOrExpr target_53, ExprStmt target_54, BlockStmt target_55, LogicalOrExpr target_56, CommaExpr target_57, BlockStmt target_58, LogicalOrExpr target_59, ArrayExpr target_60, ExprStmt target_61, ExprStmt target_62, ExprStmt target_63, ExprStmt target_64, LogicalOrExpr target_65, BlockStmt target_66, RelationalOperation target_67, PointerArithmeticOperation target_68
where
func_0(vdatao_218, target_0)
and func_1(vdatao_218, target_49, target_1)
and func_2(vo_218, target_2)
and func_3(vo_218, target_50, target_3)
and func_4(vdataofs_303, target_4)
and not func_5(vbuf_size_215, vdatao_218)
and not func_6(vbuf_size_215, target_53)
and not func_7(vbuf_size_215, vo_218, target_54, target_53)
and not func_9(vbuf_size_215, vo_218, target_55, target_56, target_57)
and not func_10(vbuf_size_215, vn_217, target_58, target_59, target_56, target_60, target_61)
and not func_13(ven_214, vn_217, target_33, target_63, target_54, target_64)
and not func_14(target_33, func)
and not func_15(ven_214, vbuf_size_215, vs_279, vdataofs_303, target_65, target_22, target_53)
and func_19(target_33, func, target_19)
and func_20(vbuf_215, vn_217, vs_279, vdataofs_303, target_33, target_20)
and func_21(vs_279, vdataofs_303, target_21)
and func_22(ven_214, vn_217, vtcount_218, vs_279, target_33, target_22)
and func_23(ven_214, vn_217, vtcount_218, vs_279, target_33, target_23)
and func_24(vbuf_215, vn_217, vtcount_218, vs_279, vdataofs_303, target_33, target_24)
and func_26(vdatao_218, target_26)
and func_28(vbuf_size_215, target_28)
and func_30(vo_218, target_30)
and func_32(vbuf_size_215, target_32)
and func_33(vs_279, target_58, target_33)
and func_34(vs_279, target_34)
and func_35(vdataofs_303, target_35)
and func_36(vs_279, target_36)
and func_37(vbuf_size_215, target_37)
and func_38(vdatao_218, target_38)
and func_39(vo_218, target_39)
and func_40(vdataofs_303, target_40)
and func_41(vdatao_218, target_41)
and func_42(vdatao_218, target_42)
and func_43(vdatao_218, target_49, target_43)
and func_44(vo_218, target_44)
and func_45(vo_218, target_45)
and func_46(vo_218, target_50, target_46)
and func_47(vs_279, vdataofs_303, target_47)
and func_48(vs_279, vdataofs_303, target_48)
and func_49(vbuf_215, vdatao_218, target_49)
and func_50(vbuf_215, vo_218, target_50)
and func_53(vbuf_size_215, target_53)
and func_54(ven_214, vbuf_size_215, vs_279, vdataofs_303, target_54)
and func_55(ven_214, target_55)
and func_56(vbuf_size_215, target_56)
and func_57(vo_218, target_57)
and func_58(ven_214, vbuf_size_215, vs_279, vdataofs_303, target_58)
and func_59(vbuf_215, vbuf_size_215, vn_217, target_59)
and func_60(vn_217, vtcount_218, target_60)
and func_61(vn_217, target_61)
and func_62(vn_217, vdatao_218, target_62)
and func_63(ven_214, vn_217, vtcount_218, target_63)
and func_64(vbuf_215, vn_217, vdataofs_303, target_64)
and func_65(vbuf_size_215, target_65)
and func_66(ven_214, vbuf_size_215, vs_279, vdataofs_303, target_66)
and func_67(vs_279, target_67)
and func_68(vbuf_215, vdataofs_303, target_68)
and ven_214.getType().hasName("ExifMnoteData *")
and vbuf_215.getType().hasName("const unsigned char *")
and vbuf_size_215.getType().hasName("unsigned int")
and vn_217.getType().hasName("ExifMnoteDataPentax *")
and vtcount_218.getType().hasName("size_t")
and vo_218.getType().hasName("size_t")
and vdatao_218.getType().hasName("size_t")
and vs_279.getType().hasName("size_t")
and vdataofs_303.getType().hasName("size_t")
and ven_214.getParentScope+() = func
and vbuf_215.getParentScope+() = func
and vbuf_size_215.getParentScope+() = func
and vn_217.getParentScope+() = func
and vtcount_218.getParentScope+() = func
and vo_218.getParentScope+() = func
and vdatao_218.getParentScope+() = func
and vs_279.getParentScope+() = func
and vdataofs_303.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
