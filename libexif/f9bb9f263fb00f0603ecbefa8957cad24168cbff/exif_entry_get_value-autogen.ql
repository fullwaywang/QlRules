/**
 * @name libexif-f9bb9f263fb00f0603ecbefa8957cad24168cbff-exif_entry_get_value
 * @id cpp/libexif/f9bb9f263fb00f0603ecbefa8957cad24168cbff/exif-entry-get-value
 * @description libexif-f9bb9f263fb00f0603ecbefa8957cad24168cbff-libexif/exif-entry.c-exif_entry_get_value CVE-2020-0182
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ventry_845, BlockStmt target_4, ExprStmt target_5, LogicalAndExpr target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="7"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Minolta"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable ventry_845, BlockStmt target_7, ExprStmt target_8, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof LogicalAndExpr
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable ventry_845, BlockStmt target_4, LogicalAndExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=ventry_845
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Minolta"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable ventry_845, BlockStmt target_7, LogicalAndExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=ventry_845
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_3.getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Variable ventry_845, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventry_845
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_content_get_entry")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ifd"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_4.getStmt(1).(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DiMAGE 7"
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3.899999999999999911"
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
}

predicate func_5(Variable ventry_845, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventry_845
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_content_get_entry")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ifd"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
}

predicate func_6(Variable ventry_845, LogicalAndExpr target_6) {
		target_6.getAnOperand() instanceof LogicalAndExpr
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Minolta"
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
}

predicate func_7(Variable ventry_845, BlockStmt target_7) {
		target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DiMAGE 7"
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3.899999999999999911"
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_845
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DiMAGE 5"
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_7.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="4.900000000000000355"
}

predicate func_8(Variable ventry_845, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventry_845
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_content_get_entry")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ifd"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
}

from Function func, Variable ventry_845, LogicalAndExpr target_2, LogicalAndExpr target_3, BlockStmt target_4, ExprStmt target_5, LogicalAndExpr target_6, BlockStmt target_7, ExprStmt target_8
where
not func_0(ventry_845, target_4, target_5, target_6)
and not func_1(ventry_845, target_7, target_8, target_3)
and func_2(ventry_845, target_4, target_2)
and func_3(ventry_845, target_7, target_3)
and func_4(ventry_845, target_4)
and func_5(ventry_845, target_5)
and func_6(ventry_845, target_6)
and func_7(ventry_845, target_7)
and func_8(ventry_845, target_8)
and ventry_845.getType().hasName("ExifEntry *")
and ventry_845.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
