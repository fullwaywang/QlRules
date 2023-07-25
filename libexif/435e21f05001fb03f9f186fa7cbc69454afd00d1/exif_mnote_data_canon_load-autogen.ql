/**
 * @name libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-exif_mnote_data_canon_load
 * @id cpp/libexif/435e21f05001fb03f9f186fa7cbc69454afd00d1/exif-mnote-data-canon-load
 * @description libexif-435e21f05001fb03f9f186fa7cbc69454afd00d1-libexif/canon/exif-mnote-data-canon.c-exif_mnote_data_canon_load CVE-2020-13112
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdatao_204, VariableAccess target_0) {
		target_0.getTarget()=vdatao_204
}

predicate func_1(Variable vdatao_204, PointerArithmeticOperation target_49, VariableAccess target_1) {
		target_1.getTarget()=vdatao_204
		and target_1.getLocation().isBefore(target_49.getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vo_204, VariableAccess target_2) {
		target_2.getTarget()=vo_204
}

predicate func_3(Variable vo_204, PointerArithmeticOperation target_50, VariableAccess target_3) {
		target_3.getTarget()=vo_204
		and target_3.getLocation().isBefore(target_50.getAnOperand().(VariableAccess).getLocation())
}

predicate func_4(Variable vdataofs_265, VariableAccess target_4) {
		target_4.getTarget()=vdataofs_265
}

predicate func_5(Parameter vbuf_size_200, Variable vdatao_204) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vdatao_204
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200)
}

predicate func_6(Parameter vbuf_size_200, LogicalOrExpr target_52) {
	exists(SubExpr target_6 |
		target_6.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_6.getRightOperand() instanceof Literal
		and target_6.getLeftOperand().(VariableAccess).getLocation().isBefore(target_52.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vbuf_size_200, Variable vo_204, ExprStmt target_53, LogicalOrExpr target_52) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vo_204
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_53.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vbuf_size_200, Variable vo_204, BlockStmt target_54, LogicalOrExpr target_55, CommaExpr target_56) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vo_204
		and target_9.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_9.getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_9.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_54
		and target_55.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_56.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vbuf_size_200, Variable vn_202, BlockStmt target_57, LogicalOrExpr target_58, LogicalOrExpr target_55, ArrayExpr target_59, ExprStmt target_60) {
	exists(LogicalAndExpr target_10 |
		target_10.getAnOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="components"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getParent().(IfStmt).getThen()=target_57
		and target_58.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_55.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_59.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Parameter vbuf_size_200, Variable vn_202, LogicalOrExpr target_58, LogicalOrExpr target_55, ExprStmt target_61) {
	exists(DivExpr target_11 |
		target_11.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_11.getRightOperand().(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_58.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(VariableAccess).getLocation())
		and target_11.getLeftOperand().(VariableAccess).getLocation().isBefore(target_55.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_61.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getRightOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_12(Variable vn_202, ExprStmt target_60) {
	exists(ValueFieldAccess target_12 |
		target_12.getTarget().getName()="components"
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_12.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_12.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Parameter vne_199, Variable vn_202, NotExpr target_19, ExprStmt target_62, ExprStmt target_53, ExprStmt target_63) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_13.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_13.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag size overflow detected (%u * %lu)"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("exif_format_get_size")
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="format"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="components"
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_13.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_62.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_53.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_14(NotExpr target_19, Function func) {
	exists(ContinueStmt target_14 |
		target_14.toString() = "continue;"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Parameter vne_199, Parameter vbuf_size_200, Variable vs_235, Variable vdataofs_265, LogicalOrExpr target_64, ExprStmt target_23, LogicalOrExpr target_52) {
	exists(IfStmt target_15 |
		target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_235
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_15.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_235
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_200
		and target_15.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_64
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_52.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_15.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_16(Parameter vbuf_size_200, Variable vdataofs_265, LogicalOrExpr target_52, LogicalOrExpr target_64) {
	exists(RelationalOperation target_16 |
		 (target_16 instanceof GEExpr or target_16 instanceof LEExpr)
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_16.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_52.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_16.getLesserOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_17(Parameter vbuf_size_200, Variable vs_235, LogicalOrExpr target_64) {
	exists(RelationalOperation target_17 |
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vs_235
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200)
}

*/
/*predicate func_18(Parameter vbuf_size_200, Variable vs_235, Variable vdataofs_265, BlockStmt target_65, RelationalOperation target_66, PointerArithmeticOperation target_67) {
	exists(RelationalOperation target_18 |
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_18.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_18.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vs_235
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_18.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
		and target_18.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_65
		and target_66.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_67.getAnOperand().(VariableAccess).getLocation().isBefore(target_18.getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_19(Variable vs_235, BlockStmt target_57, NotExpr target_19) {
		target_19.getOperand().(VariableAccess).getTarget()=vs_235
		and target_19.getParent().(IfStmt).getThen()=target_57
}

predicate func_20(NotExpr target_19, Function func, DeclStmt target_20) {
		target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Parameter vbuf_200, Variable vn_202, Variable vs_235, Variable vdataofs_265, NotExpr target_19, IfStmt target_21) {
		target_21.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_235
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_265
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_21.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_22(Variable vs_235, Variable vdataofs_265, AddExpr target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_22.getAnOperand().(VariableAccess).getTarget()=vs_235
}

predicate func_23(Parameter vne_199, Variable vn_202, Variable vtcount_204, Variable vs_235, NotExpr target_19, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_204
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_mem_alloc")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_235
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_24(Parameter vne_199, Variable vn_202, Variable vtcount_204, Variable vs_235, NotExpr target_19, IfStmt target_24) {
		target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_24.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_204
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Could not allocate %lu byte(s)."
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_235
		and target_24.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_25(Parameter vbuf_200, Variable vn_202, Variable vtcount_204, Variable vs_235, Variable vdataofs_265, NotExpr target_19, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_204
		and target_25.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_25.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_25.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_235
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_27(Variable vdatao_204, VariableAccess target_27) {
		target_27.getTarget()=vdatao_204
}

predicate func_29(Parameter vbuf_size_200, VariableAccess target_29) {
		target_29.getTarget()=vbuf_size_200
}

predicate func_31(Variable vo_204, VariableAccess target_31) {
		target_31.getTarget()=vo_204
}

predicate func_33(Parameter vbuf_size_200, VariableAccess target_33) {
		target_33.getTarget()=vbuf_size_200
}

predicate func_34(Variable vs_235, VariableAccess target_34) {
		target_34.getTarget()=vs_235
}

predicate func_35(Variable vs_235, VariableAccess target_35) {
		target_35.getTarget()=vs_235
}

predicate func_36(Variable vdataofs_265, VariableAccess target_36) {
		target_36.getTarget()=vdataofs_265
}

predicate func_37(Parameter vbuf_size_200, VariableAccess target_37) {
		target_37.getTarget()=vbuf_size_200
}

predicate func_38(Variable vdatao_204, VariableAccess target_38) {
		target_38.getTarget()=vdatao_204
}

predicate func_39(Variable vo_204, VariableAccess target_39) {
		target_39.getTarget()=vo_204
}

predicate func_40(Variable vdataofs_265, VariableAccess target_40) {
		target_40.getTarget()=vdataofs_265
}

predicate func_41(Variable vdatao_204, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatao_204
		and target_41.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_41.getGreaterOperand().(VariableAccess).getTarget()=vdatao_204
}

predicate func_42(Variable vdatao_204, AddExpr target_42) {
		target_42.getAnOperand().(VariableAccess).getTarget()=vdatao_204
		and target_42.getAnOperand().(Literal).getValue()="2"
}

predicate func_43(Variable vdatao_204, PointerArithmeticOperation target_49, AddExpr target_43) {
		target_43.getAnOperand().(VariableAccess).getTarget()=vdatao_204
		and target_43.getAnOperand().(Literal).getValue()="2"
		and target_43.getAnOperand().(VariableAccess).getLocation().isBefore(target_49.getAnOperand().(VariableAccess).getLocation())
}

predicate func_44(Variable vo_204, RelationalOperation target_44) {
		 (target_44 instanceof GTExpr or target_44 instanceof LTExpr)
		and target_44.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_204
		and target_44.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_44.getGreaterOperand().(VariableAccess).getTarget()=vo_204
}

predicate func_45(Variable vo_204, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_204
		and target_45.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_45.getGreaterOperand() instanceof Literal
}

predicate func_46(Variable vo_204, PointerArithmeticOperation target_50, AddExpr target_46) {
		target_46.getAnOperand().(VariableAccess).getTarget()=vo_204
		and target_46.getAnOperand().(Literal).getValue()="12"
		and target_46.getAnOperand().(VariableAccess).getLocation().isBefore(target_50.getAnOperand().(VariableAccess).getLocation())
}

predicate func_47(Variable vs_235, Variable vdataofs_265, RelationalOperation target_47) {
		 (target_47 instanceof GTExpr or target_47 instanceof LTExpr)
		and target_47.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_47.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_235
		and target_47.getGreaterOperand().(VariableAccess).getTarget()=vs_235
}

predicate func_48(Variable vs_235, Variable vdataofs_265, RelationalOperation target_48) {
		 (target_48 instanceof GTExpr or target_48 instanceof LTExpr)
		and target_48.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_48.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_235
		and target_48.getGreaterOperand().(VariableAccess).getTarget()=vdataofs_265
}

predicate func_49(Parameter vbuf_200, Variable vdatao_204, PointerArithmeticOperation target_49) {
		target_49.getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_49.getAnOperand().(VariableAccess).getTarget()=vdatao_204
}

predicate func_50(Parameter vbuf_200, Variable vo_204, PointerArithmeticOperation target_50) {
		target_50.getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_50.getAnOperand().(VariableAccess).getTarget()=vo_204
}

predicate func_52(Parameter vbuf_size_200, LogicalOrExpr target_52) {
		target_52.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_52.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_52.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_52.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_53(Parameter vne_199, Parameter vbuf_size_200, Variable vs_235, Variable vdataofs_265, ExprStmt target_53) {
		target_53.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_53.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_53.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_53.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_53.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_53.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_53.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_235
		and target_53.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_54(Parameter vne_199, BlockStmt target_54) {
		target_54.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_54.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_54.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_54.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_54.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Short MakerNote"
}

predicate func_55(Parameter vbuf_size_200, LogicalOrExpr target_55) {
		target_55.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_55.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_55.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_55.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_55.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_56(Variable vo_204, CommaExpr target_56) {
		target_56.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vo_204
		and target_56.getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="12"
}

predicate func_57(Parameter vne_199, BlockStmt target_57) {
		target_57.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_57.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_57.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_57.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_57.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid zero-length tag size"
}

predicate func_58(Parameter vbuf_200, Parameter vbuf_size_200, Variable vn_202, LogicalOrExpr target_58) {
		target_58.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vn_202
		and target_58.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_200
		and target_58.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_59(Variable vn_202, Variable vtcount_204, ArrayExpr target_59) {
		target_59.getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_59.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_59.getArrayOffset().(VariableAccess).getTarget()=vtcount_204
}

predicate func_60(Parameter vbuf_200, Variable vn_202, Variable vdatao_204, ExprStmt target_60) {
		target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_get_short")
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdatao_204
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
}

predicate func_61(Variable vn_202, Variable vdatao_204, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdatao_204
		and target_61.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_61.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_61.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
}

predicate func_62(Parameter vne_199, ExprStmt target_62) {
		target_62.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_62.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_62.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_62.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_62.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid zero-length tag size"
}

predicate func_63(Parameter vbuf_200, Variable vn_202, Variable vdataofs_265, ExprStmt target_63) {
		target_63.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdataofs_265
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("exif_get_long")
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="order"
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_202
		and target_63.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
}

predicate func_64(Parameter vbuf_size_200, LogicalOrExpr target_64) {
		target_64.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_64.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_64.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_64.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_65(Parameter vne_199, Parameter vbuf_size_200, Variable vs_235, Variable vdataofs_265, BlockStmt target_65) {
		target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_199
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data past end of buffer (%u > %u)"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdataofs_265
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_235
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuf_size_200
}

predicate func_66(Variable vs_235, RelationalOperation target_66) {
		 (target_66 instanceof GTExpr or target_66 instanceof LTExpr)
		and target_66.getGreaterOperand().(VariableAccess).getTarget()=vs_235
		and target_66.getLesserOperand().(Literal).getValue()="4"
}

predicate func_67(Parameter vbuf_200, Variable vdataofs_265, PointerArithmeticOperation target_67) {
		target_67.getAnOperand().(VariableAccess).getTarget()=vbuf_200
		and target_67.getAnOperand().(VariableAccess).getTarget()=vdataofs_265
}

from Function func, Parameter vne_199, Parameter vbuf_200, Parameter vbuf_size_200, Variable vn_202, Variable vtcount_204, Variable vo_204, Variable vdatao_204, Variable vs_235, Variable vdataofs_265, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, NotExpr target_19, DeclStmt target_20, IfStmt target_21, AddExpr target_22, ExprStmt target_23, IfStmt target_24, ExprStmt target_25, VariableAccess target_27, VariableAccess target_29, VariableAccess target_31, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, VariableAccess target_36, VariableAccess target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, RelationalOperation target_41, AddExpr target_42, AddExpr target_43, RelationalOperation target_44, RelationalOperation target_45, AddExpr target_46, RelationalOperation target_47, RelationalOperation target_48, PointerArithmeticOperation target_49, PointerArithmeticOperation target_50, LogicalOrExpr target_52, ExprStmt target_53, BlockStmt target_54, LogicalOrExpr target_55, CommaExpr target_56, BlockStmt target_57, LogicalOrExpr target_58, ArrayExpr target_59, ExprStmt target_60, ExprStmt target_61, ExprStmt target_62, ExprStmt target_63, LogicalOrExpr target_64, BlockStmt target_65, RelationalOperation target_66, PointerArithmeticOperation target_67
where
func_0(vdatao_204, target_0)
and func_1(vdatao_204, target_49, target_1)
and func_2(vo_204, target_2)
and func_3(vo_204, target_50, target_3)
and func_4(vdataofs_265, target_4)
and not func_5(vbuf_size_200, vdatao_204)
and not func_6(vbuf_size_200, target_52)
and not func_7(vbuf_size_200, vo_204, target_53, target_52)
and not func_9(vbuf_size_200, vo_204, target_54, target_55, target_56)
and not func_10(vbuf_size_200, vn_202, target_57, target_58, target_55, target_59, target_60)
and not func_13(vne_199, vn_202, target_19, target_62, target_53, target_63)
and not func_14(target_19, func)
and not func_15(vne_199, vbuf_size_200, vs_235, vdataofs_265, target_64, target_23, target_52)
and func_19(vs_235, target_57, target_19)
and func_20(target_19, func, target_20)
and func_21(vbuf_200, vn_202, vs_235, vdataofs_265, target_19, target_21)
and func_22(vs_235, vdataofs_265, target_22)
and func_23(vne_199, vn_202, vtcount_204, vs_235, target_19, target_23)
and func_24(vne_199, vn_202, vtcount_204, vs_235, target_19, target_24)
and func_25(vbuf_200, vn_202, vtcount_204, vs_235, vdataofs_265, target_19, target_25)
and func_27(vdatao_204, target_27)
and func_29(vbuf_size_200, target_29)
and func_31(vo_204, target_31)
and func_33(vbuf_size_200, target_33)
and func_34(vs_235, target_34)
and func_35(vs_235, target_35)
and func_36(vdataofs_265, target_36)
and func_37(vbuf_size_200, target_37)
and func_38(vdatao_204, target_38)
and func_39(vo_204, target_39)
and func_40(vdataofs_265, target_40)
and func_41(vdatao_204, target_41)
and func_42(vdatao_204, target_42)
and func_43(vdatao_204, target_49, target_43)
and func_44(vo_204, target_44)
and func_45(vo_204, target_45)
and func_46(vo_204, target_50, target_46)
and func_47(vs_235, vdataofs_265, target_47)
and func_48(vs_235, vdataofs_265, target_48)
and func_49(vbuf_200, vdatao_204, target_49)
and func_50(vbuf_200, vo_204, target_50)
and func_52(vbuf_size_200, target_52)
and func_53(vne_199, vbuf_size_200, vs_235, vdataofs_265, target_53)
and func_54(vne_199, target_54)
and func_55(vbuf_size_200, target_55)
and func_56(vo_204, target_56)
and func_57(vne_199, target_57)
and func_58(vbuf_200, vbuf_size_200, vn_202, target_58)
and func_59(vn_202, vtcount_204, target_59)
and func_60(vbuf_200, vn_202, vdatao_204, target_60)
and func_61(vn_202, vdatao_204, target_61)
and func_62(vne_199, target_62)
and func_63(vbuf_200, vn_202, vdataofs_265, target_63)
and func_64(vbuf_size_200, target_64)
and func_65(vne_199, vbuf_size_200, vs_235, vdataofs_265, target_65)
and func_66(vs_235, target_66)
and func_67(vbuf_200, vdataofs_265, target_67)
and vne_199.getType().hasName("ExifMnoteData *")
and vbuf_200.getType().hasName("const unsigned char *")
and vbuf_size_200.getType().hasName("unsigned int")
and vn_202.getType().hasName("ExifMnoteDataCanon *")
and vtcount_204.getType().hasName("size_t")
and vo_204.getType().hasName("size_t")
and vdatao_204.getType().hasName("size_t")
and vs_235.getType().hasName("size_t")
and vdataofs_265.getType().hasName("size_t")
and vne_199.getParentScope+() = func
and vbuf_200.getParentScope+() = func
and vbuf_size_200.getParentScope+() = func
and vn_202.getParentScope+() = func
and vtcount_204.getParentScope+() = func
and vo_204.getParentScope+() = func
and vdatao_204.getParentScope+() = func
and vs_235.getParentScope+() = func
and vdataofs_265.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
