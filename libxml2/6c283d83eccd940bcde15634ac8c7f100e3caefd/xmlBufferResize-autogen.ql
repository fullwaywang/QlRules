/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferResize
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufferResize
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferResize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_7460, Variable vnewSize_7462) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7462
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7460
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7460
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7462
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess)
}

predicate func_3(Parameter vsize_7460, Variable vnewSize_7462) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7460
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_3.getThen().(AddExpr).getValue()="4294967295"
		and target_3.getElse() instanceof AddExpr
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7462)
}

predicate func_4(Function func) {
	exists(EmptyStmt target_4 |
		target_4.toString() = ";"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vsize_7460, Variable vnewSize_7462) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vnewSize_7462
		and target_5.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7460
		and target_5.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_5.getRValue().(ConditionalExpr).getThen().(AddExpr).getValue()="4294967295"
		and target_5.getRValue().(ConditionalExpr).getElse() instanceof AddExpr)
}

predicate func_7(Parameter vbuf_7460) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="size"
		and target_7.getQualifier().(VariableAccess).getTarget()=vbuf_7460)
}

predicate func_9(Parameter vsize_7460, Variable vnewSize_7462) {
	exists(AddExpr target_9 |
		target_9.getAnOperand().(VariableAccess).getTarget()=vsize_7460
		and target_9.getAnOperand().(Literal).getValue()="10"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7462)
}

predicate func_11(Parameter vsize_7460) {
	exists(RelationalOperation target_11 |
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vsize_7460
		and target_11.getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlTreeErrMemory")
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="growing buffer"
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_12(Parameter vsize_7460, Variable vnewSize_7462) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vsize_7460
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vnewSize_7462)
}

from Function func, Parameter vbuf_7460, Parameter vsize_7460, Variable vnewSize_7462
where
not func_0(vsize_7460, vnewSize_7462)
and not func_3(vsize_7460, vnewSize_7462)
and not func_4(func)
and not func_5(vsize_7460, vnewSize_7462)
and func_7(vbuf_7460)
and func_9(vsize_7460, vnewSize_7462)
and vbuf_7460.getType().hasName("xmlBufferPtr")
and vsize_7460.getType().hasName("unsigned int")
and func_11(vsize_7460)
and func_12(vsize_7460, vnewSize_7462)
and vnewSize_7462.getType().hasName("unsigned int")
and vbuf_7460.getParentScope+() = func
and vsize_7460.getParentScope+() = func
and vnewSize_7462.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
