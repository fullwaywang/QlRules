/**
 * @name curl-20f9dd6bae50b-cookie_output
 * @id cpp/curl/20f9dd6bae50b/cookie-output
 * @description curl-20f9dd6bae50b-cookie_output CVE-2022-32207
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrandsuffix_1644, Parameter vdata_1622) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("Curl_rand_hex")
		and not target_0.getTarget().hasName("Curl_fopen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_1622
		and target_0.getArgument(1).(VariableAccess).getTarget()=vrandsuffix_1644
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="9"
		and target_0.getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vrandsuffix_1644)
}

predicate func_1(Variable vout_1626, Variable vtempstore_1628, Variable verror_1629, Parameter vfilename_1623, Parameter vdata_1622) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=verror_1629
		and target_1.getRValue().(FunctionCall).getTarget().hasName("Curl_fopen")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_1622
		and target_1.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfilename_1623
		and target_1.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vout_1626
		and target_1.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtempstore_1628)
}

predicate func_5(Variable vtempstore_1628) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(VariableAccess).getTarget()=vtempstore_1628
		and target_5.getAnOperand() instanceof FunctionCall
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("unlink")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtempstore_1628
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ...")
}

predicate func_6(Variable verror_1629) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_1629
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_8(Variable vout_1626, Variable vuse_stdout_1627) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1626
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_stdout_1627)
}

predicate func_9(Variable vout_1626, Variable vuse_stdout_1627) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vout_1626
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_stdout_1627)
}

predicate func_10(Variable vtempstore_1628, Parameter vfilename_1623) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("Curl_rename")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vtempstore_1628
		and target_10.getArgument(1).(VariableAccess).getTarget()=vfilename_1623)
}

predicate func_15(Function func) {
	exists(GotoStmt target_15 |
		target_15.toString() = "goto ..."
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter vfilename_1623) {
	exists(DeclStmt target_16 |
		target_16.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="-"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfilename_1623)
}

predicate func_17(Variable vrandsuffix_1644) {
	exists(VariableAccess target_17 |
		target_17.getTarget()=vrandsuffix_1644)
}

predicate func_18(Function func) {
	exists(ReturnStmt target_18 |
		target_18.getExpr().(Literal).getValue()="2"
		and target_18.getParent().(IfStmt).getCondition() instanceof FunctionCall
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Variable vtempstore_1628, Variable vrandsuffix_1644, Parameter vfilename_1623) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(VariableAccess).getTarget()=vtempstore_1628
		and target_19.getRValue().(FunctionCall).getTarget().hasName("curl_maprintf")
		and target_19.getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s.%s.tmp"
		and target_19.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfilename_1623
		and target_19.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrandsuffix_1644)
}

predicate func_22(Variable vout_1626, Variable vtempstore_1628, Parameter vfilename_1623) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vout_1626
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fopen")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtempstore_1628
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="w"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="-"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfilename_1623)
}

predicate func_23(Variable vout_1626) {
	exists(NotExpr target_23 |
		target_23.getOperand().(VariableAccess).getTarget()=vout_1626
		and target_23.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_23.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof GotoStmt)
}

predicate func_24(Variable vtempstore_1628, Variable verror_1629, Function func) {
	exists(IfStmt target_24 |
		target_24.getCondition() instanceof NotExpr
		and target_24.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_24.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_24.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition() instanceof FunctionCall
		and target_24.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("unlink")
		and target_24.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtempstore_1628
		and target_24.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_1629
		and target_24.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24)
}

from Function func, Variable vout_1626, Variable vuse_stdout_1627, Variable vtempstore_1628, Variable verror_1629, Variable vrandsuffix_1644, Parameter vfilename_1623, Parameter vdata_1622
where
func_0(vrandsuffix_1644, vdata_1622)
and not func_1(vout_1626, vtempstore_1628, verror_1629, vfilename_1623, vdata_1622)
and not func_5(vtempstore_1628)
and func_6(verror_1629)
and func_8(vout_1626, vuse_stdout_1627)
and func_9(vout_1626, vuse_stdout_1627)
and func_10(vtempstore_1628, vfilename_1623)
and func_15(func)
and func_16(vfilename_1623)
and func_17(vrandsuffix_1644)
and func_18(func)
and func_19(vtempstore_1628, vrandsuffix_1644, vfilename_1623)
and func_22(vout_1626, vtempstore_1628, vfilename_1623)
and func_23(vout_1626)
and func_24(vtempstore_1628, verror_1629, func)
and vout_1626.getType().hasName("FILE *")
and vuse_stdout_1627.getType().hasName("bool")
and vtempstore_1628.getType().hasName("char *")
and verror_1629.getType().hasName("CURLcode")
and vrandsuffix_1644.getType().hasName("unsigned char[9]")
and vfilename_1623.getType().hasName("const char *")
and vdata_1622.getType().hasName("Curl_easy *")
and vout_1626.getParentScope+() = func
and vuse_stdout_1627.getParentScope+() = func
and vtempstore_1628.getParentScope+() = func
and verror_1629.getParentScope+() = func
and vrandsuffix_1644.getParentScope+() = func
and vfilename_1623.getParentScope+() = func
and vdata_1622.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
