/**
 * @name http-parser-31232735c6a44036083da685c8dff253da78c99e-http_parser_parse_url
 * @id cpp/http-parser/31232735c6a44036083da685c8dff253da78c99e/http-parser-parse-url
 * @description http-parser-31232735c6a44036083da685c8dff253da78c99e-http_parser.c-http_parser_parse_url 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuflen_2309, RelationalOperation target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuflen_2309
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_0.getLocation().isBefore(target_1.getLocation()))
}

predicate func_1(Parameter vbuflen_2309, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuflen_2309
}

from Function func, Parameter vbuflen_2309, RelationalOperation target_1
where
not func_0(vbuflen_2309, target_1)
and func_1(vbuflen_2309, target_1)
and vbuflen_2309.getType().hasName("size_t")
and vbuflen_2309.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
