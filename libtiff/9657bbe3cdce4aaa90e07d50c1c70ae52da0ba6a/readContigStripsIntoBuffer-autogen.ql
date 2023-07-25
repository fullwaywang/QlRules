/**
 * @name libtiff-9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a-readContigStripsIntoBuffer
 * @id cpp/libtiff/9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a/readContigStripsIntoBuffer
 * @description libtiff-9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a-tools/tiffcrop.c-readContigStripsIntoBuffer CVE-2016-10092
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vbytes_read_3676, LogicalAndExpr target_2, VariableAccess target_1) {
		target_1.getTarget()=vbytes_read_3676
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vbytes_read_3676, LogicalAndExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_read_3676
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vbytes_read_3676, VariableAccess target_1, LogicalAndExpr target_2
where
func_1(vbytes_read_3676, target_2, target_1)
and func_2(vbytes_read_3676, target_2)
and vbytes_read_3676.getType().hasName("int32")
and vbytes_read_3676.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
