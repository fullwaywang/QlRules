/**
 * @name wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-decompress_lz4
 * @id cpp/wireshark/f4374967bbf9c12746b8ec3cd54dddada9dd353e/decompress-lz4
 * @description wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-epan/dissectors/packet-kafka.c-decompress_lz4 CVE-2020-26418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vret_1627) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vret_1627
		and target_2.getRValue().(NotExpr).getValue()="1")
}

predicate func_3(Variable vret_1627, AssignExpr target_3) {
		target_3.getLValue().(VariableAccess).getTarget()=vret_1627
		and target_3.getRValue() instanceof Literal
}

from Function func, Variable vret_1627, Literal target_1, AssignExpr target_3
where
func_1(func, target_1)
and not func_2(vret_1627)
and func_3(vret_1627, target_3)
and vret_1627.getType().hasName("int")
and vret_1627.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
