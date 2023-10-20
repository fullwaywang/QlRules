/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-_getObjectDescription
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/-getObjectDescription
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-_getObjectDescription CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="%s %s"
		and not target_0.getValue()="%s "
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vbuf_3426, Parameter vte_3426, LogicalOrExpr target_4, ExprStmt target_5, FunctionCall target_3, ExprStmt target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="namespace"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_3426
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="namespace"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_3426
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s."
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="namespace"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_3426
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vbuf_3426, LogicalOrExpr target_4, ExprStmt target_6) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vbuf_3426, Parameter vte_3426, FunctionCall target_3) {
		target_3.getTarget().hasName("fmtId")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="tag"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_3426
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_4(LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SERVER"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="PUBLICATION"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SUBSCRIPTION"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="USER MAPPING"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vbuf_3426, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof FunctionCall
}

predicate func_6(Parameter vbuf_3426, Parameter vte_3426, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="LARGE OBJECT %s"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="tag"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_3426
}

from Function func, Parameter vbuf_3426, Parameter vte_3426, StringLiteral target_0, FunctionCall target_3, LogicalOrExpr target_4, ExprStmt target_5, ExprStmt target_6
where
func_0(func, target_0)
and not func_1(vbuf_3426, vte_3426, target_4, target_5, target_3, target_6)
and not func_2(vbuf_3426, target_4, target_6)
and func_3(vbuf_3426, vte_3426, target_3)
and func_4(target_4)
and func_5(vbuf_3426, target_5)
and func_6(vbuf_3426, vte_3426, target_6)
and vbuf_3426.getType().hasName("PQExpBuffer")
and vte_3426.getType().hasName("TocEntry *")
and vbuf_3426.getFunction() = func
and vte_3426.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
