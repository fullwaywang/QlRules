/**
 * @name libxml2-213f1fe0d76d30eaed6e5853057defc43e6df2c9-xmlBufGrowInternal
 * @id cpp/libxml2/213f1fe0d76d30eaed6e5853057defc43e6df2c9/xmlBufGrowInternal
 * @description libxml2-213f1fe0d76d30eaed6e5853057defc43e6df2c9-buf.c-xmlBufGrowInternal CVE-2015-1819
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_435, Parameter vlen_435, Variable vsize_436, ExprStmt target_1, LogicalAndExpr target_2, AddExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_435
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_435
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_435
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_435
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="buffer error: text too long\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_436
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_436
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10000000"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_435, Parameter vlen_435, Variable vsize_436, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_436
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_435
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_435
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="100"
}

predicate func_2(Parameter vbuf_435, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_435
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="contentIO"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_435
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vsize_436, AddExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_3.getAnOperand().(VariableAccess).getTarget()=vsize_436
}

from Function func, Parameter vbuf_435, Parameter vlen_435, Variable vsize_436, ExprStmt target_1, LogicalAndExpr target_2, AddExpr target_3
where
not func_0(vbuf_435, vlen_435, vsize_436, target_1, target_2, target_3, func)
and func_1(vbuf_435, vlen_435, vsize_436, target_1)
and func_2(vbuf_435, target_2)
and func_3(vsize_436, target_3)
and vbuf_435.getType().hasName("xmlBufPtr")
and vlen_435.getType().hasName("size_t")
and vsize_436.getType().hasName("size_t")
and vbuf_435.getFunction() = func
and vlen_435.getFunction() = func
and vsize_436.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
