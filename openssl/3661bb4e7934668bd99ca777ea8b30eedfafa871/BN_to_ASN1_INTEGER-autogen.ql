/**
 * @name openssl-3661bb4e7934668bd99ca777ea8b30eedfafa871-BN_to_ASN1_INTEGER
 * @id cpp/openssl/3661bb4e7934668bd99ca777ea8b30eedfafa871/BN-to-ASN1-INTEGER
 * @description openssl-3661bb4e7934668bd99ca777ea8b30eedfafa871-BN_to_ASN1_INTEGER 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbn_409, Variable vret_411) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbn_409
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_411
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="258")
}

predicate func_1(Parameter vbn_409, Variable vret_411) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="neg"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbn_409
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_411
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="258")
}

from Function func, Parameter vbn_409, Variable vret_411
where
not func_0(vbn_409, vret_411)
and func_1(vbn_409, vret_411)
and vbn_409.getType().hasName("const BIGNUM *")
and vret_411.getType().hasName("ASN1_INTEGER *")
and vbn_409.getParentScope+() = func
and vret_411.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
