/**
 * @name imagemagick-89a1c73ee2693ded91a72d00bdf3aba410f349f1-ReadPDFImage
 * @id cpp/imagemagick/89a1c73ee2693ded91a72d00bdf3aba410f349f1/ReadPDFImage
 * @description imagemagick-89a1c73ee2693ded91a72d00bdf3aba410f349f1-coders/pdf.c-ReadPDFImage CVE-2020-29599
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voption_383, FunctionCall target_0) {
		target_0.getTarget().hasName("strpbrk")
		and not target_0.getTarget().hasName("SanitizeDelegateString")
		and target_0.getArgument(0).(VariableAccess).getTarget()=voption_383
		and target_0.getArgument(1).(StringLiteral).getValue()="&;<>|\"'"
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="\"-sPDFPassword=%s\" "
		and not target_1.getValue()="'-sPDFPassword=%s' "
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Variable voption_383, LogicalAndExpr target_8, ExprStmt target_10) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("char *")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("SanitizeDelegateString")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voption_383
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_4(Variable vpassphrase_598, LogicalAndExpr target_8, ExprStmt target_11) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpassphrase_598
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="'-sPDFPassword=%s' "
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("char *")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(LogicalAndExpr target_8, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyString")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable voption_383, BlockStmt target_12, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=voption_383
		and target_7.getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_8(BlockStmt target_12, Function func, LogicalAndExpr target_8) {
		target_8.getAnOperand() instanceof EqualityOperation
		and target_8.getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(IfStmt).getThen()=target_12
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable voption_383, Variable vpassphrase_598, LogicalAndExpr target_8, ExprStmt target_11, VariableAccess target_9) {
		target_9.getTarget()=voption_383
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpassphrase_598
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_10(Variable voption_383, Variable vpassphrase_598, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpassphrase_598
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_10.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_10.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voption_383
}

predicate func_11(Variable vpassphrase_598, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("ConcatenateMagickString")
		and target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpassphrase_598
		and target_11.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4096"
}

predicate func_12(Variable voption_383, Variable vpassphrase_598, BlockStmt target_12) {
		target_12.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_12.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpassphrase_598
		and target_12.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_12.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_12.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voption_383
}

from Function func, Variable voption_383, Variable vpassphrase_598, FunctionCall target_0, StringLiteral target_1, EqualityOperation target_7, LogicalAndExpr target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, BlockStmt target_12
where
func_0(voption_383, target_0)
and func_1(func, target_1)
and not func_3(voption_383, target_8, target_10)
and not func_4(vpassphrase_598, target_8, target_11)
and not func_6(target_8, func)
and func_7(voption_383, target_12, target_7)
and func_8(target_12, func, target_8)
and func_9(voption_383, vpassphrase_598, target_8, target_11, target_9)
and func_10(voption_383, vpassphrase_598, target_10)
and func_11(vpassphrase_598, target_11)
and func_12(voption_383, vpassphrase_598, target_12)
and voption_383.getType().hasName("const char *")
and vpassphrase_598.getType().hasName("char[4096]")
and voption_383.getParentScope+() = func
and vpassphrase_598.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
