/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddRef
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlAddRef
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-valid.c-xmlAddRef CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2973, BlockStmt target_3, ExprStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlIsStreaming")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_2973
		and target_0.getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_2973, VariableAccess target_1) {
		target_1.getTarget()=vctxt_2973
}

predicate func_2(Parameter vctxt_2973, BlockStmt target_3, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_2973
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vstateNr"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2973
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_3
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlRefPtr")
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
}

predicate func_4(Parameter vctxt_2973, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("xmlVErrMemory")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2973
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="malloc failed"
}

from Function func, Parameter vctxt_2973, VariableAccess target_1, LogicalAndExpr target_2, BlockStmt target_3, ExprStmt target_4
where
not func_0(vctxt_2973, target_3, target_4)
and func_1(vctxt_2973, target_1)
and func_2(vctxt_2973, target_3, target_2)
and func_3(target_3)
and func_4(vctxt_2973, target_4)
and vctxt_2973.getType().hasName("xmlValidCtxtPtr")
and vctxt_2973.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
