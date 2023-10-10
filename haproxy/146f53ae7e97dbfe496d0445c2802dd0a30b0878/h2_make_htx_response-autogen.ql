/**
 * @name haproxy-146f53ae7e97dbfe496d0445c2802dd0a30b0878-h2_make_htx_response
 * @id cpp/haproxy/146f53ae7e97dbfe496d0445c2802dd0a30b0878/h2-make-htx-response
 * @description haproxy-146f53ae7e97dbfe496d0445c2802dd0a30b0878-src/h2.c-h2_make_htx_response CVE-2019-19330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_577, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="32"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_577
}

predicate func_1(Variable vphdr_575, Variable vi_577, ExprStmt target_4) {
	exists(NotExpr target_1 |
		target_1.getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vphdr_575
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_577
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vi_577, GotoStmt target_5, PostfixIncrExpr target_6, RelationalOperation target_3) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand() instanceof RelationalOperation
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t[256]")
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="n"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_577
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_2.getParent().(IfStmt).getThen()=target_5
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vlist_570, Variable vidx_574, Variable vi_577, GotoStmt target_5, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="n"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlist_570
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_574
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_577
		and target_3.getLesserOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="65"
		and target_3.getGreaterOperand().(SubExpr).getValue()="25"
		and target_3.getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vlist_570, Variable vidx_574, Variable vphdr_575, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphdr_575
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="n"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlist_570
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_574
}

predicate func_5(GotoStmt target_5) {
		target_5.toString() = "goto ..."
		and target_5.getName() ="fail"
}

predicate func_6(Variable vi_577, PostfixIncrExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vi_577
}

from Function func, Parameter vlist_570, Variable vidx_574, Variable vphdr_575, Variable vi_577, Literal target_0, RelationalOperation target_3, ExprStmt target_4, GotoStmt target_5, PostfixIncrExpr target_6
where
func_0(vi_577, target_0)
and not func_1(vphdr_575, vi_577, target_4)
and not func_2(vi_577, target_5, target_6, target_3)
and func_3(vlist_570, vidx_574, vi_577, target_5, target_3)
and func_4(vlist_570, vidx_574, vphdr_575, target_4)
and func_5(target_5)
and func_6(vi_577, target_6)
and vlist_570.getType().hasName("http_hdr *")
and vidx_574.getType().hasName("uint32_t")
and vphdr_575.getType().hasName("int")
and vi_577.getType().hasName("int")
and vlist_570.getParentScope+() = func
and vidx_574.getParentScope+() = func
and vphdr_575.getParentScope+() = func
and vi_577.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
