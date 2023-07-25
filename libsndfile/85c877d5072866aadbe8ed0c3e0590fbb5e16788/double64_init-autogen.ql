/**
 * @name libsndfile-85c877d5072866aadbe8ed0c3e0590fbb5e16788-double64_init
 * @id cpp/libsndfile/85c877d5072866aadbe8ed0c3e0590fbb5e16788/double64-init
 * @description libsndfile-85c877d5072866aadbe8ed0c3e0590fbb5e16788-src/double64.c-double64_init CVE-2017-14634
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpsf_91, BlockStmt target_2, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_91
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1024"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpsf_91, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_91
		and target_1.getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vpsf_91, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psf_log_printf")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpsf_91
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="double64_init : internal error : channels = %d\n"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="channels"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_91
}

from Function func, Parameter vpsf_91, RelationalOperation target_1, BlockStmt target_2
where
not func_0(vpsf_91, target_2, target_1)
and func_1(vpsf_91, target_2, target_1)
and func_2(vpsf_91, target_2)
and vpsf_91.getType().hasName("SF_PRIVATE *")
and vpsf_91.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
