/**
 * @name linux-d1f82808877bb10d3deee7cf3374a4eb3fb582db-io_add_buffers
 * @id cpp/linux/d1f82808877bb10d3deee7cf3374a4eb3fb582db/io-add-buffers
 * @description linux-d1f82808877bb10d3deee7cf3374a4eb3fb582db-io_add_buffers CVE-2021-3491
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpbuf_3977, Variable vbuf_3979) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_3979
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpbuf_3977
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpbuf_3977
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getValue()="2147479552"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpbuf_3977
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("__u32")
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("__u32")
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("__u32")
		and target_0.getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("__u32"))
}

predicate func_4(Parameter vpbuf_3977) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="len"
		and target_4.getQualifier().(VariableAccess).getTarget()=vpbuf_3977
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue() instanceof PointerFieldAccess)
}

predicate func_6(Variable vbuf_3979) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_3979
		and target_6.getRValue() instanceof PointerFieldAccess)
}

predicate func_7(Parameter vpbuf_3977) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="nbufs"
		and target_7.getQualifier().(VariableAccess).getTarget()=vpbuf_3977)
}

from Function func, Parameter vpbuf_3977, Variable vbuf_3979
where
not func_0(vpbuf_3977, vbuf_3979)
and func_4(vpbuf_3977)
and func_6(vbuf_3979)
and vpbuf_3977.getType().hasName("io_provide_buf *")
and func_7(vpbuf_3977)
and vbuf_3979.getType().hasName("io_buffer *")
and vpbuf_3977.getParentScope+() = func
and vbuf_3979.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
