/**
 * @name openssl-c62981390d6cf9e3d612c489b8b77c2913b25807-asn1_d2i_read_bio
 * @id cpp/openssl/c62981390d6cf9e3d612c489b8b77c2913b25807/asn1-d2i-read-bio
 * @description openssl-c62981390d6cf9e3d612c489b8b77c2913b25807-asn1_d2i_read_bio CVE-2016-2109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwant_146) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vwant_146)
}

predicate func_3(Variable vwant_146) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vwant_146)
}

predicate func_4(Variable vwant_146, Variable voff_148, Variable vlen_149) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(MulExpr).getValue()="16384"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwant_146
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_149
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_148)
}

predicate func_5(Variable vb_143, Variable vi_145, Variable vwant_146, Variable voff_148, Variable vlen_149) {
	exists(WhileStmt target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwant_146
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vwant_146
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_143
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_149
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vwant_146
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_145
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_read")
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_145
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_149
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vi_145
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vi_145
		and target_5.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="1073741823"
		and target_5.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignMulExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_5.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignMulExpr).getRValue().(Literal).getValue()="2"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwant_146
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_149
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_148)
}

predicate func_10(Variable vwant_146, Variable vlen_149) {
	exists(LogicalOrExpr target_10 |
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwant_146
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_149
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vwant_146
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_149
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="155"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_11(Variable vb_143, Variable vwant_146, Variable vlen_149) {
	exists(AddExpr target_11 |
		target_11.getAnOperand().(VariableAccess).getTarget()=vlen_149
		and target_11.getAnOperand().(VariableAccess).getTarget()=vwant_146
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_143)
}

from Function func, Variable vb_143, Variable vi_145, Parameter vin_141, Variable vwant_146, Variable voff_148, Variable vlen_149
where
func_0(vwant_146)
and func_3(vwant_146)
and not func_4(vwant_146, voff_148, vlen_149)
and not func_5(vb_143, vi_145, vwant_146, voff_148, vlen_149)
and vb_143.getType().hasName("BUF_MEM *")
and vi_145.getType().hasName("int")
and vin_141.getType().hasName("BIO *")
and vwant_146.getType().hasName("size_t")
and func_10(vwant_146, vlen_149)
and func_11(vb_143, vwant_146, vlen_149)
and voff_148.getType().hasName("size_t")
and vlen_149.getType().hasName("size_t")
and vb_143.getParentScope+() = func
and vi_145.getParentScope+() = func
and vin_141.getParentScope+() = func
and vwant_146.getParentScope+() = func
and voff_148.getParentScope+() = func
and vlen_149.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
