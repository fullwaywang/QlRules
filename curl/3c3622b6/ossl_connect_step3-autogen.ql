/**
 * @name curl-3c3622b6-ossl_connect_step3
 * @id cpp/curl/3c3622b6/ossl-connect-step3
 * @description curl-3c3622b6-lib/ssluse.c-ossl_connect_step3 CVE-2013-4545
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_2294, ExprStmt target_2, ExprStmt target_3, ValueFieldAccess target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="verifyhost"
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2294
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_2294, ExprStmt target_2, NotExpr target_1) {
		target_1.getOperand().(ValueFieldAccess).getTarget().getName()="verifypeer"
		and target_1.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_1.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2294
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("servercert")
		and target_2.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_3(Variable vdata_2294, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2294
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="failed to store ssl session"
}

predicate func_4(Variable vdata_2294, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="ssl"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2294
}

from Function func, Variable vdata_2294, NotExpr target_1, ExprStmt target_2, ExprStmt target_3, ValueFieldAccess target_4
where
not func_0(vdata_2294, target_2, target_3, target_4)
and func_1(vdata_2294, target_2, target_1)
and func_2(target_2)
and func_3(vdata_2294, target_3)
and func_4(vdata_2294, target_4)
and vdata_2294.getType().hasName("SessionHandle *")
and vdata_2294.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
